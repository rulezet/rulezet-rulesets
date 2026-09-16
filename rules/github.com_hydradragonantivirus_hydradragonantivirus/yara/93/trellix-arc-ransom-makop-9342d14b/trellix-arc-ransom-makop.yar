rule TRELLIX_ARC_RANSOM_Makop: RANSOMWARE FILE {
  meta:
    description    = "Rule to detect the unpacked Makop ransomware samples"
    author         = "Marc Rivero | McAfee ATR Team"
    id             = "2828f2f9-4702-5cef-8b4e-7e98146c0332"
    date           = "2020-07-19"
    modified       = "2020-08-14"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_makop.yar#L1-L32"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    hash           = "008e4c327875110b96deef1dd8ef65cefa201fef60ca1cbb9ab51b5304e66fe1"
    logic_hash     = "2b4f8b90d46530421b66dbb04df6e84d268709fbee884536d8acc91e1b85f8a4"
    score          = 75
    quality        = 70
    tags           = "RANSOMWARE, FILE"
    rule_version   = "v1"
    malware_type   = "ransomware"
    malware_family = "Ransom:W32/Makop"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"

  strings:
    $pattern_0 = { 50 8d 7c 24 20 e8 ?? ?? ?? ?? 84 c0 0f 84 a6 02 00 00 8b 74 24 60 ba ?? ?? ?? ?? }
    $pattern_1 = { 51 52 53 ff d5 85 c0 74 6d 8b 4c 24 0c }
    $pattern_2 = { 75 21 68 00 00 00 f0 6a 18 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? }
    $pattern_3 = { 83 c4 0c 8d 4e 0c 51 66 c7 06 08 02 66 c7 46 04 10 66 c6 46 08 20 }
    $pattern_4 = { 51 ff d3 50 ff d7 8b 46 28 85 c0 }
    $pattern_5 = { 85 c9 74 1e 8b 45 08 8b 4d 0c 8a 11 }
    $pattern_6 = { 83 c0 02 66 85 c9 75 f5 2b c6 d1 f8 66 39 0c 46 8d 34 46 }
    $pattern_7 = { 89 5a 2c 8b 7f 04 85 ff 0f 85 f7 fe ff ff 55 6a 00 }
    $pattern_8 = { 8b 3d ?? ?? ?? ?? 6a 01 6a 00 ff d7 50 ff 15 ?? ?? ?? ?? }
    $pattern_9 = { 85 c0 74 07 50 ff 15 ?? ?? ?? ?? }

  condition:
    7 of them and filesize < 237568
}