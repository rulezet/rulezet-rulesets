rule TRELLIX_ARC_Wannaren_Ransomware: RANSOMWARE FILE {
  meta:
    description    = "Rule to detect WannaRen Ransomware"
    author         = "McAfee ATR Team"
    id             = "f4f30d12-547d-5044-a4e5-b88bf359480f"
    date           = "2020-04-25"
    modified       = "2020-10-12"
    reference      = "https://blog.360totalsecurity.com/en/attention-you-may-have-become-a-susceptible-group-of-wannaren-ransomware/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_wannaren.yar#L1-L34"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    hash           = "7b364f1c854e6891c8d09766bcc9a49420e0b5b4084d74aa331ae94e2cfb7e1d"
    logic_hash     = "0feb913b84eb0ecdda688f0cf0a5051798fe4fbce8a6ea959825985a81a6699c"
    score          = 75
    quality        = 70
    tags           = "RANSOMWARE, FILE"
    rule_version   = "v1"
    malware_type   = "ransomware"
    malware_family = "Ransom:W32/WannaRen"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"

  strings:
    $sq0 = { 92 93 a9 1c 2e a5 21 59 33 48 26 }
    $sq1 = { d0 ce 66 41 c1 e9 c0 41 80 f6 52 49 c1 f9 4d }
    $sq2 = { 80 f8 b5 4d 63 c9 f9 4d 03 d9 41 }
    $sq3 = { 34 b7 d2 ea 66 0f ba fa 56 0f 99 c2 32 d8 66 0f ba fa ed 99 }
    $sq4 = { f9 f7 c7 00 12 35 5f 35 c0 1f 52 26 f9 8d 80 56 c8 00 b0 f6 c4 b2 f9 }
    $sq5 = { f5 f9 44 3a eb 45 33 cd 41 }
    $sq6 = { 89 0f c0 ff 12 44 b4 a3 ee 2b 4e 70 73 61 }
    $sq7 = { 81 c5 02 00 00 00 66 89 54 25 00 66 81 d9 7a 1e 66 0f ab e1 66 0f ba e1 a5 8b 0f 8d bf 04 00 00 00 }
    $sq8 = { 8d 13 de 11 d7 67 78 46 f1 0d 8c d4 5f 87 bb 34 b9 8f 33 }
    $sq9 = { 14 40 4b 41 e8 ?? ?? ?? ?? 39 7c 08 47 }

  condition:
    uint16(0) == 0x5a4d and filesize < 21000KB and 7 of them
}