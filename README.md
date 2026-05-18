# 🛡️ Laporan Teknis: Wazuh SIEM Lab — DDoS Detection & Analysis

**Mata Kuliah:** Manajemen Infrastruktur Keamanan Siber (MIKS)  
**Institusi:** Institut Teknologi Sepuluh Nopember (ITS)  
**Kelompok:** Kelompok2  

---

## 📋 Daftar Isi

1. [Ringkasan Eksekutif](#1-ringkasan-eksekutif)
2. [Arsitektur Infrastruktur](#2-arsitektur-infrastruktur)
3. [Pembagian Tugas Kelompok](#3-pembagian-tugas-kelompok)
4. [Fase 1 — Setup Azure & VM (Orang 1: Shinta)](#4-fase-1--setup-azure--vm-orang-1-shinta)
5. [Fase 2 — Konfigurasi Wazuh Stack (Orang 2: Angga)](#5-fase-2--konfigurasi-wazuh-stack-orang-2-angga)
6. [Fase 3 — Simulasi Serangan DDoS (Orang 3: Hafis)](#6-fase-3--simulasi-serangan-ddos-orang-3-hafis)
7. [Fase 4 — Analisis Log & Deteksi (Orang 4: Zaenal)](#7-fase-4--analisis-log--deteksi-orang-4-zaenal)
8. [Custom Detection Rules](#8-custom-detection-rules)
9. [Integrasi ClamAV — Malware Detection](#9-integrasi-clamav--malware-detection)
10. [Analisis Log Density](#10-analisis-log-density)
11. [Hasil & Temuan](#11-hasil--temuan)
12. [Kesimpulan & Rekomendasi](#12-kesimpulan--rekomendasi)

---

## 1. Ringkasan Eksekutif

Laporan ini mendokumentasikan implementasi lengkap platform **Wazuh SIEM** di atas infrastruktur **Microsoft Azure**, beserta simulasi serangan **Distributed Denial of Service (DDoS)** sebagai Proof of Concept (PoC) untuk membuktikan kemampuan deteksi anomali jaringan.

### Tujuan Tugas

| # | Tujuan |
|---|--------|
| 1 | Deploy arsitektur Wazuh lengkap (Manager + 2 Agent) di Azure cloud |
| 2 | Mengembangkan skenario simulasi serangan DDoS yang komprehensif |
| 3 | Membuktikan kemampuan Wazuh mendeteksi pola traffic anomali dan menghasilkan alert kritis |
| 4 | Menganalisis *logging density* dan dampak volume log terhadap performa SIEM |

### Hasil Singkat

✅ Wazuh Manager + Indexer + Dashboard berhasil di-deploy  
✅ 2 Wazuh Agent terhubung dan aktif  
✅ 3 jenis serangan DDoS berhasil dieksekusi dan **terdeteksi**  
✅ Custom rules (DDoS + ClamAV) berhasil dibuat dan divalidasi  
✅ Fenomena *log density overflow* berhasil direproduksi dan dianalisis  

---

## 2. Arsitektur Infrastruktur

### Topologi Jaringan

```
┌─────────────────────────────────────────────────────────────┐
│                   Azure VNet: wazuh-manager-vnet             │
│                     Subnet: 10.0.0.0/24                      │
│                                                              │
│  ┌──────────────────┐    Port 1514 (TCP)    ┌─────────────┐ │
│  │  wazuh-manager   │◄─────────────────────│wazuh-agent-1│ │
│  │  10.0.0.4        │                       │  10.0.0.5   │ │
│  │  (Manager +      │    Port 1514 (TCP)    │  (TARGET)   │ │
│  │   Indexer +      │◄─────────────────────└─────────────┘ │
│  │   Dashboard)     │                                       │
│  │                  │    Port 1514 (TCP)    ┌─────────────┐ │
│  └──────────────────┘◄─────────────────────│wazuh-agent-2│ │
│                                             │  10.0.0.6   │ │
│                                             │  (ATTACKER) │ │
│                                             └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Spesifikasi Virtual Machine

| VM | Nama | IP Public | IP Private | Size | OS |
|----|------|-----------|------------|------|----|
| Manager | `wazuh-manager` | `70.153.86.7` | `10.0.0.4` | Standard B2s v2 (2 vCPU, 8 GiB) | Ubuntu 24.04 LTS |
| Agent 1 | `wazuh-agent-1` | `70.153.151.52` | `10.0.0.5` | Standard B2als v2 (2 vCPU, 4 GiB) | Ubuntu 24.04 LTS |
| Agent 2 | `wazuh-agent-2` | `48.193.46.1` | `10.0.0.6` | Standard B2als v2 (2 vCPU, 4 GiB) | Ubuntu 24.04 LTS |

### Konfigurasi NSG (Network Security Group)

| Priority | Name | Port | Protocol | Source | Action |
|----------|------|------|----------|--------|--------|
| 110 | Allow-HTTPS | 443 | TCP | Any | Allow |
| 120 | Allow-Agent-Log | 1514 | Any | VirtualNetwork | Allow |
| 130 | Allow-Enrollment | 1515 | TCP | VirtualNetwork | Allow |
| 140 | Allow-REST-API | 55000 | TCP | VirtualNetwork | Allow |
| 300 | SSH | 22 | TCP | Any | Allow |

### Stack Komponen Wazuh

```
wazuh-manager VM
├── Wazuh Manager      → Engine analisis & korelasi log
├── Wazuh Indexer      → Database OpenSearch (port 9200)
├── Wazuh Dashboard    → Web UI (port 443)
└── Filebeat           → Jembatan Manager ↔ Indexer
```

---

## 3. Pembagian Tugas Kelompok

| Orang | Nama | Peran | Tanggung Jawab |
|-------|------|-------|----------------|
| 1 | Shinta | Cloud Engineer | Setup Azure, VM provisioning, install Wazuh stack |
| 2 | Angga | SIEM Engineer | Konfigurasi Filebeat, koneksi agent, verifikasi stack |
| 3 | Hafis | Security Tester | Eksekusi serangan DDoS, dokumentasi bukti deteksi |
| 4 | Zaenal | Security Analyst | Analisis log, custom rules, laporan teknis final |

---

## 4. Fase 1 — Setup Azure & VM (Orang 1: Shinta)

### 4.1 Pembuatan Resource Group

**Resource Group:** `wazuh-lab-rg`  
**Region:** Indonesia Central (`indonesiacentral`)  
**Subscription:** Azure for Students

Tag yang diterapkan:

```
Project     = WazuhLab
Owner       = ITS-Kelompok2
Environment = Lab
```

> Region `indonesiacentral` dipilih karena merupakan salah satu region yang diizinkan oleh policy ITS, bersama `centralindia`, `malaysiawest`, `eastasia`, dan `koreacentral`.

### 4.2 Instalasi Azure CLI

```powershell
# Install dari https://aka.ms/installazurecliwindows
# Login ke subscription
az login

# Verifikasi policy region
az policy assignment list --query "[0].parameters" -o json
```

### 4.3 Provisioning VM Wazuh Manager

**Konfigurasi utama:**

| Parameter | Nilai |
|-----------|-------|
| VM Name | `wazuh-manager` |
| Region | Asia Pacific — Indonesia Central |
| Image | Ubuntu Server 24.04 LTS — x64 Gen2 |
| Size | Standard B2s v2 (2 vCPU, 8 GiB) |
| Auth | SSH Public Key (`wazuh-manager-key.pem`) |
| Disk | 64 GiB Premium SSD |
| VNet | `wazuh-manager-vnet` |
| Subnet | `default (10.0.0.0/24)` |

### 4.4 Koneksi SSH ke VM Manager

```powershell
# Fix permission file .pem
icacls "C:\path\to\wazuh-manager-key.pem" /inheritance:r /grant:r "$($env:USERNAME):(R)"

# SSH ke Manager
ssh -i "C:\path\to\wazuh-manager-key.pem" azureuser@70.153.86.7
```

### 4.5 Instalasi Wazuh Manager

```bash
# Update sistem
sudo apt-get update && sudo apt-get upgrade -y

# Tambah Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg \
  --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
  --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update

# Install & jalankan Wazuh Manager
sudo apt-get install wazuh-manager -y
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

### 4.6 Instalasi Wazuh Indexer

```bash
sudo apt-get install wazuh-indexer -y

# Generate SSL certificates
curl -sO https://packages.wazuh.com/4.4/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.4/config.yml
```

**Konfigurasi `config.yml`:**

```yaml
nodes:
  indexer:
    - name: wazuh-manager
      ip: 127.0.0.1
  server:
    - name: wazuh-manager
      ip: 127.0.0.1
  dashboard:
    - name: wazuh-manager
      ip: 127.0.0.1
```

**Konfigurasi `/etc/wazuh-indexer/opensearch.yml`:**

```yaml
network.host: 0.0.0.0
node.name: "wazuh-manager"
cluster.initial_master_nodes:
  - "wazuh-manager"
```

```bash
# Generate & deploy certificates
sudo bash wazuh-certs-tool.sh -A
sudo mkdir -p /etc/wazuh-indexer/certs
sudo cp -r ~/wazuh-certificates/. /etc/wazuh-indexer/certs/
sudo chmod 500 /etc/wazuh-indexer/certs
sudo find /etc/wazuh-indexer/certs -type f -exec chmod 400 {} \;
sudo chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# Rename cert sesuai kebutuhan
sudo cp /etc/wazuh-indexer/certs/wazuh-manager.pem \
        /etc/wazuh-indexer/certs/indexer.pem
sudo cp /etc/wazuh-indexer/certs/wazuh-manager-key.pem \
        /etc/wazuh-indexer/certs/indexer-key.pem

sudo systemctl enable wazuh-indexer
sudo systemctl start wazuh-indexer
```

### 4.7 Instalasi Wazuh Dashboard

```bash
sudo apt-get install wazuh-dashboard -y
```

**Konfigurasi `/etc/wazuh-dashboard/opensearch_dashboards.yml`:**

```yaml
server.host: 0.0.0.0
opensearch.hosts: https://localhost:9200
```

```bash
sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard
```

### 4.8 Provisioning VM Agent

2 VM agent dibuat dengan spesifikasi:
- **Image:** Ubuntu Server 24.04 LTS — x64 Gen2  
- **Size:** Standard B2als v2 (2 vCPU, 4 GiB)  
- **SSH Key:** Menggunakan `wazuh-manager-key` yang sudah tersimpan di Azure  
- **VNet:** Bergabung ke `wazuh-manager-vnet` (VNet yang sama dengan Manager)

---

## 5. Fase 2 — Konfigurasi Wazuh Stack (Orang 2: Angga)

### 5.1 Verifikasi Service

```bash
sudo systemctl status wazuh-manager    # harus active (running)
sudo systemctl status wazuh-indexer    # harus active (running)
sudo systemctl status wazuh-dashboard  # harus active (running)
```

**Troubleshooting Dashboard Certificate:**

Jika `wazuh-dashboard` terus restart karena certificate belum ada:

```bash
sudo mkdir -p /etc/wazuh-dashboard/certs
sudo cp /etc/wazuh-indexer/certs/wazuh-manager.pem \
        /etc/wazuh-dashboard/certs/dashboard.pem
sudo cp /etc/wazuh-indexer/certs/wazuh-manager-key.pem \
        /etc/wazuh-dashboard/certs/dashboard-key.pem
sudo cp /etc/wazuh-indexer/certs/root-ca.pem \
        /etc/wazuh-dashboard/certs/root-ca.pem
sudo chmod 400 /etc/wazuh-dashboard/certs/*.pem
sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
sudo systemctl restart wazuh-dashboard
```

### 5.2 Inisialisasi Security Indexer

```bash
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh
# Tunggu 1-2 menit — output "Done with success" = berhasil
```

### 5.3 Instalasi & Konfigurasi Filebeat

Filebeat adalah komponen kritis sebagai **jembatan antara Wazuh Manager dan Indexer**. Tanpa Filebeat, data tidak akan masuk ke dashboard meskipun semua service berjalan.

```bash
sudo apt-get install filebeat -y

# Download konfigurasi resmi Wazuh untuk Filebeat
sudo curl -so /etc/filebeat/filebeat.yml \
  https://raw.githubusercontent.com/wazuh/wazuh/v4.7.5/extensions/filebeat/7.x/filebeat.yml
```

**Konfigurasi `/etc/filebeat/filebeat.yml` (bagian `output.elasticsearch`):**

```yaml
output.elasticsearch:
  hosts: ['https://127.0.0.1:9200']
  username: 'admin'
  password: 'admin'
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: /etc/filebeat/certs/filebeat.pem
  ssl.key: /etc/filebeat/certs/filebeat-key.pem
```

```bash
# Copy certificates ke Filebeat
sudo mkdir -p /etc/filebeat/certs
sudo cp /etc/wazuh-indexer/certs/wazuh-manager.pem     /etc/filebeat/certs/filebeat.pem
sudo cp /etc/wazuh-indexer/certs/wazuh-manager-key.pem /etc/filebeat/certs/filebeat-key.pem
sudo cp /etc/wazuh-indexer/certs/root-ca.pem           /etc/filebeat/certs/root-ca.pem
sudo chmod 400 /etc/filebeat/certs/*.pem

# Download Wazuh template
sudo curl -so /etc/filebeat/wazuh-template.json \
  https://raw.githubusercontent.com/wazuh/wazuh/v4.7.5/extensions/elasticsearch/7.x/wazuh-template.json

curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.3.tar.gz | \
  sudo tar -xvz -C /usr/share/filebeat/module

# Jalankan Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Verifikasi koneksi ke Indexer
sudo filebeat test output
# Output yang benar: parse url...OK | dial up...OK | handshake...OK | talk to server...OK
```

### 5.4 Instalasi Wazuh Agent di VM Agent-1 & Agent-2

Dijalankan di **masing-masing** VM agent:

```bash
sudo apt-get update

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg \
  --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
  --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update

# Install agent sekaligus daftarkan ke Manager (IP private)
WAZUH_MANAGER="10.0.0.4" sudo apt-get install wazuh-agent -y

sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent   # harus active (running)
```

### 5.5 Konfigurasi Logging IPTables di Agent-1

Agar Wazuh dapat membaca log traffic jaringan (untuk deteksi DDoS), IPTables Agent-1 dikonfigurasi untuk mencatat paket masuk ke `kern.log`:

```bash
# Pasang iptables logging rules
sudo iptables -I INPUT -p tcp --syn -j LOG --log-prefix "SYN-FLOOD: "  --log-level 4
sudo iptables -I INPUT -p udp       -j LOG --log-prefix "UDP-FLOOD: "  --log-level 4
sudo iptables -I INPUT -p icmp      -j LOG --log-prefix "ICMP-FLOOD: " --log-level 4
```

Daftarkan `kern.log` ke Wazuh Agent — tambahkan di `/var/ossec/etc/ossec.conf` sebelum `</ossec_config>`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

### 5.6 Verifikasi Agent Terdaftar

```bash
# Di VM Manager
sudo /var/ossec/bin/agent_control -l
```

**Output yang diharapkan:**

```
ID: 000, Name: wazuh-manager, IP: 127.0.0.1, Status: Active/Local
ID: 001, Name: wazuh-agent-1, IP: any,       Status: Active
ID: 002, Name: wazuh-agent-2, IP: any,       Status: Active
```

**Hasil:** Kedua agent berhasil terdaftar dengan status **Active** ✅

---

## 6. Fase 3 — Simulasi Serangan DDoS (Orang 3: Hafis)

> ⚠️ **Disclaimer:** Seluruh serangan hanya diarahkan ke infrastruktur lab sendiri (`wazuh-agent-1`, IP: `10.0.0.5`) untuk keperluan akademik. Tidak ada serangan yang diarahkan ke infrastruktur eksternal.

### 6.1 Setup Attacker — Instalasi hping3 di Agent-2

```bash
sudo apt-get update
sudo apt-get install hping3 -y
hping3 --version   # verifikasi instalasi
```

**Topologi Serangan:**
- **Attacker:** `wazuh-agent-2` (10.0.0.6)
- **Target:** `wazuh-agent-1` (10.0.0.5)
- **Tool:** `hping3`
- **Pemantauan:** Wazuh Dashboard + `alerts.log` di Manager

### 6.2 Serangan 1 — SYN Flood

**Deskripsi:**  
SYN Flood mengirim ribuan paket TCP SYN tanpa pernah menyelesaikan three-way handshake, menghabiskan resource koneksi pada target.

**Eksekusi (dari Agent-2):**

```bash
sudo hping3 -S --flood -V -p 80 10.0.0.5
# -S        : flag SYN
# --flood   : kirim secepat mungkin
# -V        : verbose
# -p 80     : target port 80 (HTTP)
```

**Statistik (sampel):**

```
HPING 10.0.0.5 (eth0 10.0.0.5): S set, 40 headers + 0 data bytes
hping in flood mode, no replies will be shown
--- 10.0.0.5 hping statistic ---
1,462,984 packets transmitted, 0 packets received, 100% packet loss
```

**Deteksi Wazuh:**

```
Rule: 100200 (level 12) → 'Possible SYN Flood attack detected via iptables'
Agent: wazuh-agent-1 | IP: 10.0.0.5
Groups: ddos, network, attack
```

### 6.3 Serangan 2 — UDP Flood

**Deskripsi:**  
UDP Flood mengirim paket UDP dalam jumlah besar ke port acak. Target terpaksa memproses tiap paket untuk mencari service yang listening, menghabiskan CPU dan bandwidth.

**Eksekusi (dari Agent-2):**

```bash
sudo hping3 --udp --flood -V -p 53 10.0.0.5
# --udp : gunakan protokol UDP
# -p 53 : target port 53 (DNS)
```

**Statistik (sampel):**

```
--- 10.0.0.5 hping statistic ---
6,445,692 packets transmitted, 0 packets received, 100% packet loss
```

**Deteksi Wazuh:**

```
Rule: 100201 (level 12) → 'Possible UDP Flood attack detected via iptables'
Agent: wazuh-agent-1 | IP: 10.0.0.5
Groups: ddos, network, attack
```

### 6.4 Serangan 3 — ICMP Flood (Ping Flood)

**Deskripsi:**  
ICMP Flood mengirim paket ICMP echo request dalam volume sangat tinggi. Karakteristik unik: volume paket ICMP jauh lebih besar dari SYN/UDP sehingga langsung memenuhi buffer agent.

**Eksekusi (dari Agent-2):**

```bash
sudo hping3 --icmp --flood -V 10.0.0.5
# --icmp : gunakan protokol ICMP
```

**Statistik (sampel):**

```
--- 10.0.0.5 hping statistic ---
5,982,903 packets transmitted, 0 packets received, 100% packet loss
```

**Deteksi:**  
Karena volume ICMP yang sangat tinggi menyebabkan buffer overflow pada agent, bukti deteksi ICMP disajikan dalam 3 lapis (lihat [Analisis Log Density](#10-analisis-log-density)).

### 6.5 Rangkuman Statistik Serangan

| Serangan | Protokol | Port Target | Paket Terkirim | Rule | Level |
|----------|----------|-------------|----------------|------|-------|
| SYN Flood | TCP | 80 | ~1,462,984 | 100200 | 12 |
| UDP Flood | UDP | 53 | ~6,445,692 | 100201 | 12 |
| ICMP Flood | ICMP | — | ~5,982,903 | 100202 | 12 |

---

## 7. Fase 4 — Analisis Log & Deteksi (Orang 4: Zaenal)

### 7.1 Verifikasi Alert di Terminal Manager

```bash
# Monitor real-time saat serangan berlangsung
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -E "100200|100201|100202|FLOOD"

# Lihat alert berdasarkan rule ID spesifik
sudo grep -i 'flood' /var/ossec/logs/alerts/alerts.log | tail -20

# Hitung total alert per rule
sudo grep -c "100200\|100201\|100202" /var/ossec/logs/alerts/alerts.log
```

**Contoh alert dari log:**

```
** Alert 1778898234.189601: - wazuh,agent_flooding,pci_dss_10.6.1,gdpr_IV_35.7.d,
Rule: 100200 (level 12) → 'Possible SYN Flood attack detected via iptables'
2026-05-17T15:09:17 wazuh-agent-1 kernel: SYN-FLOOD: IN=eth0 OU
T= MAC=7c:1e:52:63:72:9c:7c:ed:8d:67:5f:0f:08:00 SRC=10.0.0.6 DST=10.0.0.5 L
EN=40 TOS=0x00 PREC=0x00 TTL=64 ID=13983 PROTO=TCP SPT=6128 DPT=80 WINDOW=51
2 RES=0x00 SYN URGP=0
```

### 7.2 Verifikasi dengan Wazuh Logtest

Untuk memvalidasi rule ICMP bekerja dengan benar:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Input (paste baris dari kern.log):

```
2026-05-17T15:25:44.937666+00:00 wazuh-agent-1 kernel: ICMP-FLOOD: IN=eth0 OUT=
MAC=7c:1e:52:63:72:9c:7c:ed:8d:67:5f:0f:08:00 SRC=10.0.0.6 DST=10.0.0.5
LEN=28 TOS=0x00 PREC=0x00 TTL=64 ID=24064 PROTO=ICMP TYPE=8 CODE=0 ID=31901 SEQ=44424
```

**Output Logtest (konfirmasi rule match):**

```
**Phase 1: Completed pre-decoding.
        program_name: 'kernel'

**Phase 2: Completed decoding.
        name: 'kernel'
        action: 'ICMP-FLOOD:'
        dstip: '10.0.0.5'
        srcip: '10.0.0.6'

**Phase 3: Completed filtering (rules).
        id: '100202'
        level: '12'
        description: 'Possible ICMP Flood attack detected via iptables'
        groups: ['ddos', 'network', 'attack']
        firedtimes: '1'
        mail: 'True'
**Alert to be generated.
```

### 7.3 Distribusi Alert per Agent

```bash
sudo grep -E '\(wazuh-agent-[12]\)' /var/ossec/logs/alerts/alerts.log \
  | grep -oP 'wazuh-agent-[12]' | sort | uniq -c | sort -rn
```

**Hasil:**

```
456 wazuh-agent-1
264 wazuh-agent-2
```

> Agent-1 (target serangan) mendominasi jumlah alert — sesuai ekspektasi.

### 7.4 Statistik Agent Detail

```bash
sudo /var/ossec/bin/agent_control -i 001
```

**Output:**

```
Wazuh agent control. Agent information:
  Agent ID:   001
  Agent Name: wazuh-agent-1
  IP address: any
  Status:     Active

  Operating system: Linux wazuh-agent-1 6.17.0-1013-azure
                    Ubuntu 24.04.4 LTS x86_64
  Client version:   Wazuh v4.14.5
  Last keep alive:  1778906363

  Syscheck last started at: Sat May 16 00:43:23 2026
  Syscheck last ended at:   Sat May 16 00:43:24 2026
```

---

## 8. Custom Detection Rules

### 8.1 DDoS Detection Rules

File: `/var/ossec/ruleset/rules/local_rules.xml`

```xml
<group name="ddos,network,attack,">

  <!-- SYN Flood Detection -->
  <rule id="100200" level="12">
    <if_sid>4100</if_sid>
    <match>SYN-FLOOD</match>
    <description>Possible SYN Flood attack detected via iptables</description>
    <group>ddos,attack,</group>
  </rule>

  <!-- UDP Flood Detection -->
  <rule id="100201" level="12">
    <if_sid>4100</if_sid>
    <match>UDP-FLOOD</match>
    <description>Possible UDP Flood attack detected via iptables</description>
    <group>ddos,attack,</group>
  </rule>

  <!-- ICMP Flood Detection -->
  <rule id="100202" level="12">
    <if_sid>4100</if_sid>
    <match>ICMP-FLOOD</match>
    <description>Possible ICMP Flood attack detected via iptables</description>
    <group>ddos,attack,</group>
  </rule>

</group>
```

### 8.2 ClamAV Malware Detection Rules

```xml
<!-- ClamAV Malware Detected -->
<rule id="100300" level="12">
  <if_sid>1</if_sid>
  <program_name>clamscan</program_name>
  <match>FOUND</match>
  <description>ClamAV detected malware on this agent</description>
  <group>malware,antivirus,attack,</group>
</rule>

<!-- EICAR Test File Detected -->
<rule id="100301" level="14">
  <if_sid>1</if_sid>
  <program_name>clamscan</program_name>
  <match>Eicar-Signature FOUND</match>
  <description>ClamAV detected EICAR test malware - malware module operational</description>
  <group>malware,antivirus,attack,</group>
</rule>
```

### 8.3 Penjelasan Teknis Rule

| Field | Penjelasan |
|-------|------------|
| `if_sid: 4100` | Parent rule: log dari kernel Linux (iptables) |
| `match: SYN-FLOOD` | Mencocokkan prefix yang ditambahkan iptables |
| `level: 12` | Level kritis — memicu notifikasi email (`rule.mail: true`) |
| `group: ddos,attack` | Klasifikasi untuk filtering di dashboard |
| `gdpr: IV_35.7.d` | Pemetaan ke standar GDPR (dihasilkan otomatis Wazuh) |
| `pci_dss: 10.6.1` | Pemetaan ke standar PCI DSS |

```bash
# Apply rules (restart Manager)
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager   # pastikan active (running)
```

---

## 9. Integrasi ClamAV — Malware Detection

### 9.1 Instalasi ClamAV di Agent-1 & Agent-2

```bash
sudo apt-get update
sudo apt-get install clamav clamav-daemon -y

# Update virus database
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

### 9.2 Buat File Test EICAR

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > /tmp/eicar_test.txt
```

> EICAR (European Institute for Computer Antivirus Research) adalah standar file test antivirus yang aman — tidak berbahaya namun dikenali semua antivirus sebagai malware.

### 9.3 Eksekusi Scan & Integrasi ke Wazuh

```bash
# Scan dan kirim output ke syslog (agar Wazuh bisa baca)
sudo clamscan /tmp/eicar_test.txt 2>&1 | sudo logger -t clamscan
```

**Output scan ClamAV:**

```
/tmp/eicar_test.txt: Eicar-Signature FOUND
----------- SCAN SUMMARY -----------
Known viruses: 3627862
Engine version: 1.4.4
Scanned files: 1
Infected files: 1
```

### 9.4 Daftarkan ClamAV Log ke Wazuh Agent

Tambahkan di `/var/ossec/etc/ossec.conf` sebelum `</ossec_config>`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/clamav/clamav.log</location>
</localfile>
```

### 9.5 Hasil Deteksi di Dashboard

**Agent-1 (Rule 100300 — level 12):**

```
predecoder.program_name: clamscan
agent.name: wazuh-agent-1
rule.id: 100300
rule.level: 12
rule.description: ClamAV detected malware on this agent
rule.groups: ddos, network, attack, malware, antivirus, attack
```

**Agent-2 (Rule 100301 — level 14):**

```
agent.name: wazuh-agent-2
rule.id: 100301
rule.level: 14
rule.description: ClamAV detected EICAR test malware - malware module operational
rule.groups: ddos, network, attack, malware, antivirus, attack
```

> Rule 100301 di-trigger dengan level **14** (lebih tinggi) karena mendeteksi signature EICAR secara spesifik — bukti modul malware berfungsi dengan benar.

---

## 10. Analisis Log Density

Salah satu poin kunci tugas adalah **"Address specific concerns regarding logging density and distribution."** Berikut analisis yang dikumpulkan selama eksperimen.

### 10.1 Perbandingan Jumlah Alert

```bash
# Hitung total alert di log
sudo grep -c '^** Alert' /var/ossec/logs/alerts/alerts.log
```

| Kondisi | Jumlah Alert |
|---------|-------------|
| Sebelum serangan | 889 |
| Selama serangan (satu sesi) | 932 |
| Sesudah semua serangan | 1,042+ |

> Lonjakan 43 alert dalam satu sesi serangan menunjukkan Wazuh berhasil menangkap anomali secara real-time.

### 10.2 Fenomena Buffer Overflow (ICMP Flood)

ICMP Flood menghasilkan volume paket yang jauh lebih tinggi dibanding SYN/UDP Flood. Hal ini menyebabkan **buffer overflow** pada Wazuh Agent:

```bash
sudo cat /var/ossec/logs/ossec.log | grep -i "buffer"
```

**Output (dari Agent-1 saat ICMP Flood):**

```
2026-05-17 15:09:28 wazuh-agentd: WARNING: Agent buffer is full: Events may be lost.
2026-05-17 15:09:43 wazuh-agentd: WARNING: Agent buffer is flooded: Producing too many events.
2026-05-17 15:09:52 wazuh-agentd: WARNING: Agent buffer is full: Events may be lost.
2026-05-17 15:13:23 wazuh-agentd: INFO: Agent buffer is under 70%. Working properly again.
```

**Rule 204 — Agent Event Queue Flooded:**

Wazuh sendiri memiliki built-in rule untuk mendeteksi kondisi ini:

```
Rule: 204 (level 12) → 'Agent event queue is flooded. Check the agent configuration.'
Groups: wazuh, agent_flooding
```

### 10.3 Analisis Distribusi Alert per Agent

```bash
sudo grep -E '\(wazuh-agent-[12]\)' /var/ossec/logs/alerts/alerts.log \
  | grep -oP 'wazuh-agent-[12]' | sort | uniq -c | sort -rn
```

```
456  wazuh-agent-1   (target — dominan saat diserang)
264  wazuh-agent-2   (attacker — audit command execution)
```

### 10.4 Implikasi & Solusi

**Masalah yang Teridentifikasi:**

> Serangan DDoS berskala besar (khususnya ICMP Flood) dapat menyebabkan **logging density problem** — Wazuh Agent kewalahan memproses log dalam jumlah sangat besar dalam waktu singkat. Sebagian alert berpotensi hilang karena buffer penuh.

**Solusi yang Dapat Diterapkan:**

| Solusi | Deskripsi |
|--------|-----------|
| Tingkatkan buffer agent | Edit `internal_options.conf` → `agent.recv_timeout` & `logcollector.queue_size` |
| Rate limiting di iptables | `--limit 10/sec` pada ICMP logging rule (sudah diterapkan di fase selanjutnya) |
| Dedicated log forwarder | Gunakan rsyslog/syslog-ng dengan queue persistent sebelum Wazuh |
| Wazuh cluster mode | Deploy multiple indexer node untuk distribusi beban |

---

## 11. Hasil & Temuan

### 11.1 Matriks Deteksi Komprehensif

| Aspek | Status | Bukti |
|-------|--------|-------|
| SYN Flood terdeteksi | ✅ | Rule 100200 — alert level 12 di dashboard |
| UDP Flood terdeteksi | ✅ | Rule 100201 — alert level 12 di dashboard |
| ICMP Flood tercatat di kernel | ✅ | `kern.log` ada entri ICMP-FLOOD |
| Rule ICMP valid | ✅ | Logtest konfirmasi Rule 100202 match |
| ClamAV malware Agent-1 | ✅ | Rule 100300 — level 12 |
| ClamAV EICAR Agent-2 | ✅ | Rule 100301 — level 14 |
| Log density problem | ✅ | Buffer overflow warning di `ossec.log` |
| Distribusi alert per agent | ✅ | Agent-1: 456, Agent-2: 264 |

### 11.2 Observasi Penting dari Dashboard

Selama serangan berlangsung, dashboard Wazuh menunjukkan:

- **Total events** melonjak signifikan (dari ~5,000 ke lebih dari 5,000+ dalam periode singkat)
- **Level 12 alerts** muncul konsisten setiap sesi serangan
- **Top 10 MITRE ATT&CK:** Masuk kategori *Remote Services* dan *Brute Force*
- **Alerts Evolution** menunjukkan spike yang jelas pada timestamp serangan

### 11.3 Temuan Teknis

1. **Rule parent `if_sid: 4100`** berhasil menangkap log kernel dari iptables. Ini adalah cara yang efisien karena memanfaatkan logging OS bawaan tanpa perlu tools tambahan.

2. **Filebeat sebagai komponen kritis** — tanpa Filebeat, data tidak masuk ke Indexer meskipun Manager berjalan. Ini sering menjadi titik kegagalan yang tidak terdiagnosis.

3. **ICMP Flood menghasilkan volume tertinggi** di antara tiga jenis serangan, membuktikan bahwa serangan layer 3 dapat lebih destruktif dari sisi logging daripada serangan layer 4.

4. **ClamAV rule 100301 (level 14)** lebih tinggi dari DDoS rules (level 12), mencerminkan bahwa deteksi malware aktif dianggap lebih kritikal daripada deteksi traffic flooding.

---

## 12. Kesimpulan & Rekomendasi

### 12.1 Kesimpulan

Proyek ini berhasil membuktikan bahwa:

1. **Wazuh SIEM dapat di-deploy secara mandiri di cloud Azure** dengan konfigurasi single-node (Manager + Indexer + Dashboard dalam satu VM) yang cukup efisien untuk lingkungan lab.

2. **Wazuh berhasil mendeteksi serangan DDoS multi-vektor** (SYN, UDP, ICMP) secara real-time dengan custom rules yang spesifik dan terklasifikasi.

3. **Log density merupakan tantangan nyata** — ICMP Flood membuktikan bahwa serangan volumetrik dapat menyebabkan event loss pada SIEM, bukan hanya pada target. Ini adalah temuan penting untuk desain arsitektur SIEM produksi.

4. **Integrasi multi-tool** (iptables + Wazuh Agent + ClamAV) menunjukkan fleksibilitas Wazuh sebagai platform SIEM yang mampu menerima log dari berbagai sumber.

### 12.2 Rekomendasi Pengembangan

| Prioritas | Rekomendasi | Alasan |
|-----------|------------|--------|
| 🔴 Tinggi | Implementasi alert throttling | Mencegah alert storm saat DDoS |
| 🔴 Tinggi | Aktifkan active response | Blokir IP attacker otomatis via iptables |
| 🟡 Sedang | Deploy Wazuh indexer cluster | Distribusi beban di produksi |
| 🟡 Sedang | Integrasi MISP threat intelligence | Enrich alert dengan IoC eksternal |
| 🟢 Rendah | Dashboard custom untuk DDoS monitoring | Visualisasi dedicated per attack type |
| 🟢 Rendah | Implementasi SOAR sederhana | Automasi respons insiden |

### 12.3 Referensi

- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [Wazuh v4.7.5 Release Notes](https://github.com/wazuh/wazuh/releases/tag/v4.7.5)
- [MITRE ATT&CK — T1498: Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
- [Azure Virtual Machine Documentation](https://docs.microsoft.com/azure/virtual-machines/)
- [EICAR Test File Standard](https://www.eicar.org/download-anti-malware-testfile/)

