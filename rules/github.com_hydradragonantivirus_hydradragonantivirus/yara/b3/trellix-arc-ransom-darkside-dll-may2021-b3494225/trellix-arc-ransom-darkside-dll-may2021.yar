rule TRELLIX_ARC_RANSOM_Darkside_DLL_May2021: RANSOM FILE {
  meta:
    description  = "Rule to detect Darkside Ransomware as a DLL"
    author       = "TS @ McAfee ATR"
    id           = "e9d64637-dc8f-5650-81e1-34e27e6ee912"
    date         = "2021-05-14"
    modified     = "2023-07-27"
    reference    = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url   = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Darkside.yar#L26-L47"
    license_url  = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    hash         = "f587adbd83ff3f4d2985453cd45c7ab1"
    logic_hash   = "39930b6f352642647ea6b80f941201b93d6a9defd42cb75f9e4f7239ff17a4ec"
    score        = 75
    quality      = 70
    tags         = "RANSOM, FILE"
    rule_type    = "Public"
    rule_version = "v1"
    malware_type = "Ransom"

  strings:
    $s1       = "encryptor2.dll" wide ascii
    $s2       = "DisableThreadLibraryCalls" wide ascii
    $s3       = "KERNEL32.dll" wide ascii
    $pattern1 = { D2 4D C8 85 5E DD 48 7B 3C D2 D5 45 F1 10 31 E1 FA 85 C2 F2 44 07 12 44 5F 67 D1 05 B3 26 53 3A 77 BA 75 B3 38 3A 98 CE 97 EA A2 B9 57 98 DC FA 6B 75 B5 57 36 62 F9 ED 5D C9 B7 D2 E5 82 FD 94 10 4E 21 0F 3E A6 2A 18 26 B2 6B 95 2F FB D5 A7 0A 97 E6 EC 3D 14 79 45 77 A2 98 0A 0E D1 EE 02 CA 29 16 23 DD 37 21 A7 E6 82 23 ED A5 6F 9E 13 25 FE 36 E1 91 D5 C4 1F 72 27 D5 5E DC 3D 5B 93 59 C8 19 }
    $pattern2 = { 87 FC 98 2E 06 6F 58 5B 73 D4 17 C0 D5 F7 5B 86 B9 F9 F8 28 6B 4C C4 2B B2 05 39 12 D5 95 A6 8C 07 C0 ED D0 15 9A C7 85 88 0C 54 83 E2 46 D3 50 1F 65 23 D0 50 78 B9 B7 51 07 11 42 39 48 D4 CB 36 7C 83 C0 83 3B D0 4A D6 DC 65 5E 1B EE A3 87 70 47 0B B4 8B 6E BA 70 94 4E 95 25 26 E4 D8 7A 03 BA A4 85 D7 B4 DA 13 18 A0 0E F0 7F A7 6C 0D }
    $pattern3 = { 1B 6F 09 9F 1C 3C 62 BB F5 54 3F A0 3B 91 9C 7B F5 E4 77 D2 56 CE 79 D9 8C 55 AC E8 D6 9C DC 93 73 B2 F0 A2 B5 14 14 77 6D 52 26 B7 4B F9 A7 CB 93 5C 9D D0 4B CF C1 9F C8 14 18 F7 A3 92 44 A7 30 69 7E 1B C0 54 18 BF 41 DE 50 E4 C8 60 95 33 59 1C E8 06 17 D4 76 E6 86 B3 6C F2 AE 91 4C B3 AF D7 20 A3 3C 0D 5D E4 38 F1 CD 0B }
    $pattern4 = { 50 60 E3 73 F1 D3 B3 BB 8D 15 C8 51 BB FC 73 F6 03 90 68 1C 48 8F 7C 0B 80 FC 2E DB C1 ED 88 CE A8 20 14 B9 22 3A 70 EA 0B B7 DD 0D 25 60 A2 9D 39 38 1F EE 7B 73 AE 22 68 3A E0 5C 36 99 18 F8 C5 77 26 78 A9 F2 9C EF 65 85 42 38 D1 C2 B7 62 CC 12 70 66 37 15 4F 57 A9 }
    $pattern5 = { EE 45 25 60 DB D5 A4 F4 6F B5 62 C9 C7 07 C8 D0 14 BB 8F 1C 18 E4 46 7E 24 9F 5A C6 9A 87 95 4F 5B 69 65 0B 7A 75 9C E2 DD 07 5E 99 CB CB A3 7A 9C 5A 06 50 ED F0 62 85 F8 F9 90 AF 6B 94 FB A0 8E 3C 0B 2E BD E3 C1 55 EC DB 06 C3 0F 95 D7 66 95 }

  condition:
    filesize >= 45KB and filesize <= 70KB and all of ($s*) and 4 of ($pattern*)
}