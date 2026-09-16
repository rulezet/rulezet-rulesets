rule TRELLIX_ARC_Netwalker: RANSOMWARE FILE {
  meta:
    description  = "Rule based on code overlap in RagnarLocker ransomware"
    author       = "McAfee ATR team"
    id           = "80097a40-534a-5e1b-8fde-e4d832d76698"
    date         = "2020-06-14"
    modified     = "2020-11-20"
    reference    = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url   = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_netwalker.yar#L49-L75"
    license_url  = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash   = "8c56ebed9e097d294045de46942c708da9ba7e01475dcecb0c3d41fcc8004780"
    score        = 75
    quality      = 70
    tags         = "RANSOMWARE, FILE"
    rule_version = "v1"
    malware_type = "ransomware"
    actor_group  = "Unknown"

  strings:
    $0 = { C8 8B F2 8B 43 30 F7 6F 38 03 C8 8B 43 48 13 F2 F7 6F 20 03 C8 8B 43 38 13 F2 F7 6F 30 03 C8 8B 43 40 13 F2 F7 6F 28 03 C8 8B 43 28 13 F2 F7 6F 40 03 C8 89 4D 68 13 F2 89 75 6C 8B 43 38 F7 6F 38 8B C8 8B F2 8B 43 28 F7 6F 48 03 C8 8B 43 48 13 F2 F7 6F 28 03 C8 8B 43 30 13 F2 F7 6F 40 0F A4 CE }
    $1 = { 89 54 24 14 89 54 24 10 8B EA 8B DA 8B FA 42 3C 22 74 7C 3C 5C 75 58 8A 02 3C 5C 74 4F 3C 2F 74 4B 3C 22 74 47 3C 62 75 07 8D 57 02 B0 08 EB 3F 3C 66 75 07 8D 53 02 B0 0C EB 34 3C 6E 75 07 8D 55 02 B0 0A EB 29 3C 72 75 0B 8B 54 24 10 B0 0D 83 C2 02 EB 1A 3C 74 75 0B 8B 54 24 14 B0 09 83 C2 }
    $2 = { C8 89 4D 70 13 F2 89 75 74 8B 43 38 F7 6F 40 8B C8 8B F2 8B 43 40 F7 6F 38 03 C8 8B 43 30 13 F2 F7 6F 48 03 C8 8B 43 48 13 F2 F7 6F 30 03 C8 89 4D 78 13 F2 89 75 7C 8B 43 48 F7 6F 38 8B C8 8B F2 8B 43 38 F7 6F 48 03 C8 8B 43 40 13 F2 F7 6F 40 0F A4 CE }
    $3 = { C0 74 39 47 3C 2F 75 E3 80 FB 2A 74 DE EB 2D 8D 4A BF 8D 42 20 80 F9 19 0F B6 D8 0F B6 C2 8A D6 0F 47 D8 8A C6 04 20 80 EA 41 0F B6 C8 80 FA 19 0F B6 C6 0F 47 C8 3A CB 75 4B 46 47 8A 16 84 D2 }
    $4 = { 8B 43 30 13 F2 F7 6F 08 03 C8 8B 43 20 13 F2 F7 6F 18 03 C8 8B 03 13 F2 F7 6F 38 03 C8 8B 43 08 13 F2 F7 6F 30 03 C8 8B 43 38 13 F2 F7 2F 03 C8 89 4D 38 13 F2 89 75 3C 8B 43 38 F7 6F 08 8B C8 }
    $5 = { F7 31 01 32 0E 32 21 32 34 32 98 32 E3 32 0C 33 2D 33 47 33 64 33 83 33 91 33 A8 33 BD 33 05 34 63 34 7C 34 54 35 64 35 83 35 AE 36 C3 36 29 37 E9 37 9A 39 BA 39 0A 3A 20 3A 44 3A 18 3B 2B 3B }
    $6 = { 8B 43 18 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 38 03 C8 8B 43 40 13 F2 F7 6F 20 0F A4 CE 01 03 C9 03 C8 8B 43 20 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 30 03 C8 89 4D 60 13 F2 89 75 64 }

  condition:
    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and all of them
}