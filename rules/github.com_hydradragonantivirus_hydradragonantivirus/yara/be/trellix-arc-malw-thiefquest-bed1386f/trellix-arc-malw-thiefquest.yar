rule TRELLIX_ARC_MALW_Thiefquest: KEYLOGGER BACKDOOR RANSOMWARE FILE {
  meta:
    description    = "Rule to detect the Evilquest/ThiefQuest malware"
    author         = "McAfee ATR Team"
    id             = "09b074f7-6899-574d-a7d6-4414509aaa78"
    date           = "2020-07-09"
    modified       = "2020-10-12"
    reference      = "https://www.bleepingcomputer.com/news/security/thiefquest-ransomware-is-a-file-stealing-mac-wiper-in-disguise/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_thiefquest.yar#L1-L46"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    hash           = "5a024ffabefa6082031dccdb1e74a7fec9f60f257cd0b1ab0f698ba2a5baca6b"
    logic_hash     = "d40a466b12188d545d3fbe2c9d7e3685dde1250ae1f25df2a72cdf93c470ae25"
    score          = 75
    quality        = 68
    tags           = "KEYLOGGER, BACKDOOR, RANSOMWARE, FILE"
    rule_version   = "v1"
    malware_type   = "keylogger, backdoor, ransomware"
    actor_type     = "Cybercrime"
    malware_family = "Ransom:OSX/ThiefQuest"

  strings:
    $pattern_0  = { 01 c1 48 83 c1 02 48 }
    $pattern_1  = { 8c 14 71 80 c1 c1 98 1c 8c }
    $pattern_2  = { d8 97 4f 0d c8 9a 9f c9 9a df 70 cd 59 53 90 }
    $pattern_3  = { d8 97 c5 6f 02 8c 23 93 a0 a4 2e 92 8e a2 c2 7a ff c2 f8 }
    $pattern_4  = { 47 70 06 ba a6 a1 cb 82 ae f9 e8 ?? ?? ?? ?? d8 a3 2b d0 d5 19 }
    $pattern_5  = { d8 98 ab 5c 75 7b 2f f2 6f 5d }
    $pattern_6  = { bc 00 7a 84 6b 2b 54 ad af 93 35 ed df 38 e6 cd d0 b2 46 }
    $pattern_7  = { ae 49 b0 0e 01 d1 45 da 61 1b 44 83 9d b6 56 69 16 74 }
    $pattern_8  = { 01 c1 48 83 c1 01 48 }
    $pattern_9  = { 6b e3 c6 5c 99 ae ed bf 37 0e 2f 47 }
    $pattern_10 = { fd d7 43 bd 18 fd 6f 06 79 37 fa }
    $pattern_11 = { 01 c2 48 83 c2 01 bf 01 00 00 00 }
    $pattern_12 = { d8 98 25 ed 44 69 29 f1 5c e1 2d }
    $pattern_13 = { d8 99 20 62 f7 f9 73 ff 90 08 5f c6 }
    $pattern_14 = { 01 c1 66 89 ca 66 89 95 ce fe ff ff e9 ?? ?? ?? ?? }
    $pattern_15 = { 01 c1 41 89 c8 44 }
    $pattern_16 = { d8 99 35 c4 87 a7 bc df fa 58 7c be 6c ad bb 3c 18 5f c4 }
    $pattern_17 = { 01 c1 48 8b 75 a8 48 }
    $pattern_18 = { 00 00 48 89 45 f8 e9 ?? ?? ?? ?? }
    $pattern_19 = { d8 99 59 d6 47 2d a2 ?? ?? ?? ?? 35 25 c7 ee c9 95 }
    $pattern_20 = { 01 c2 48 83 c2 03 bf 01 00 00 00 }
    $pattern_21 = { 4a 78 88 ab 23 e7 cf 11 f3 }
    $pattern_22 = { d8 98 2f bf 22 2d 49 92 1d 25 b4 2b ba }
    $pattern_23 = { e2 d7 84 37 6b 46 96 d9 92 9d a6 }

  condition:
    7 of them and filesize < 124322606
}