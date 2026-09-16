rule TRELLIX_ARC_RANSOM_Mountlocker: RANSOMWARE FILE {
  meta:
    description    = "Rule to detect Mount Locker ransomware"
    author         = "McAfee ATR Team"
    id             = "8451b78c-3cef-557a-a2e3-0767a0b0eddb"
    date           = "2020-09-25"
    modified       = "2020-10-12"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_mountlocker.yar#L1-L32"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "fb332a6725b9276cca379dd3621943c69f88570fb317da27a857a2544d2aa4e0"
    score          = 75
    quality        = 64
    tags           = "RANSOMWARE, FILE"
    rule_version   = "v1"
    malware_type   = "ransomware"
    malware_family = "Ransomware:W32/MountLocker"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"
    hash1          = "4b917b60f4df6d6d08e895d179a22dcb7c38c6a6a6f39c96c3ded10368d86273"
    hash2          = "f570d5b17671e6f3e56eae6ad87be3a6bbfac46c677e478618afd9f59bf35963"

  strings:
    $s1 = "cid=%CLIENT_ID"
    $s2 = "zsa3wxvbb7gv65wnl7lerslee3c7i27ndqghqm6jt2priva2qcdponad.onion"
    $s3 = "6mlzahkc7vejytppbqhqjou4ipftgs3gizof2x4zklblliayhsqb3wad.onion"

  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and ($s1 and $s2) or ($s1 and $s3) or $s1
}