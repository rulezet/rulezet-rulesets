rule TRELLIX_ARC_Masslogger_Stealer: STEALER FILE {
  meta:
    description    = "Rule to detect unpacked MassLogger stealer"
    author         = "Marc Rivero | McAfee ATR Team"
    id             = "c3a40108-3f0c-5949-9201-95c3c38b352a"
    date           = "2020-07-02"
    modified       = "2020-08-14"
    reference      = "https://urlhaus.abuse.ch/browse/signature/MassLogger/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_masslogger_stealer.yar#L1-L63"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    hash           = "343873155b6950386f7d9bcd8d2b2e81088521aedf8ff1333d20229426d8145c"
    logic_hash     = "476b3f3a54a4616058a2aef01adbe429a38eacc8ee58881d31bd28e795a27575"
    score          = 75
    quality        = 66
    tags           = "STEALER, FILE"
    rule_version   = "v1"
    malware_type   = "stealer"
    malware_family = "Stealer:W32/MassLogger"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"

  strings:
    $pattern_0  = { 64 37 3e 25 85 82 9c 88 ec ec 1b c8 }
    $pattern_1  = { d7 b9 51 3e 1b a7 19 5a b6 e6 df 7e 2a 5a b6 cc }
    $pattern_2  = { 80 ae e2 81 aa e2 80 8e e2 80 8c e2 80 8e e2 80 8e e2 80 ae 00 43 6f 6e }
    $pattern_3  = { 6d e5 86 4c 40 }
    $pattern_4  = { e2 81 ab e2 80 8e e2 80 ae e2 81 aa e2 80 8e e2 }
    $pattern_5  = { 6c 69 63 6b 65 64 45 76 65 6e 74 41 72 67 73 00 }
    $pattern_6  = { 6e 7e 81 d8 6a af 61 93 7c 2b 83 2b 62 }
    $pattern_7  = { 8b 1c 87 e7 ed 24 a2 32 18 73 df 53 }
    $pattern_8  = { ee 9a 35 7f 9a 47 53 99 31 88 ee f9 7d 50 3f ef c9 }
    $pattern_9  = { 44 a2 ?? ?? ?? ?? 92 75 26 42 20 8f b5 ca 70 50 }
    $pattern_10 = { f2 bb af b0 d5 f8 d5 24 0d 48 c9 06 ba 79 77 5d }
    $pattern_11 = { 74 8f 46 4e 49 2a f2 ee 9a 35 7f 9a 47 53 99 }
    $pattern_12 = { 23 7d db e2 00 95 46 99 37 }
    $pattern_13 = { d9 ae 1d 19 ec 3b 01 db c5 61 5c ec }
    $pattern_14 = { 30 4a 8a e2 f4 bd e7 a8 4f 79 c0 38 d3 19 7c ea e6 }
    $pattern_15 = { 29 1f ff 84 c3 bd 55 d8 dc f3 31 f2 1a 3a 9c 7d 78 }
    $pattern_16 = { 3f 7a f1 77 a2 24 ae 7f f3 }
    $pattern_17 = { d1 65 5d 72 36 38 73 c1 b5 9e }
    $pattern_18 = { 2a ff 95 55 28 ff 94 53 }
    $pattern_19 = { e6 b1 43 08 d2 ef 43 3c 38 }
    $pattern_20 = { 69 64 42 72 75 73 68 00 43 6f 6c 6f 72 00 e2 81 }
    $pattern_21 = { 37 00 54 00 a7 87 7f 08 54 00 e1 87 53 03 5c }
    $pattern_22 = { 6a 45 e4 2c d3 ba 76 c4 f0 58 ce 30 37 }
    $pattern_23 = { b5 9e 59 f1 f1 }
    $pattern_24 = { 79 88 cd 09 91 00 99 66 4e 03 91 00 82 88 49 00 61 00 8c 88 d3 09 99 00 }
    $pattern_25 = { 1e e3 c2 00 ff 69 88 76 be 8f b3 65 b1 3e b7 45 }
    $pattern_26 = { 3d 4c 9d ea df 57 dd eb 97 }
    $pattern_27 = { e2 80 8e e2 80 8e e2 81 ae e2 80 8e e2 81 ac e2 81 ac e2 80 ad e2 80 ab e2 81 }
    $pattern_28 = { 4d 9c 8e 57 53 32 41 4f d2 8a 71 73 e2 c4 7e e4 d9 ae 1d 19 ec 3b }
    $pattern_29 = "tripMenu_Sa"
    $pattern_30 = { 79 bc fa ad 49 }
    $pattern_31 = { 87 53 03 5c 00 14 0a 37 00 5c 00 a7 }
    $pattern_32 = { 72 65 5f 43 6c 69 63 6b 00 74 6f 6f 6c 53 }
    $pattern_33 = { 36 e6 33 2b 2b 36 73 d1 d4 80 12 4d 2d }
    $pattern_34 = { 19 b3 e7 ab 29 db 51 e1 f3 dd 3a 26 6f b8 84 c4 b5 3b }
    $pattern_35 = { 74 67 43 f3 32 d2 84 bf 3d f2 e6 6b 4a ba 5a 20 d9 f5 3d bf 2a 37 53 }
    $pattern_36 = { f2 71 f3 88 77 f7 a8 e5 64 37 3e 25 85 82 9c 88 }
    $pattern_37 = { ce 84 60 4c 3f 8c c6 56 bf 16 5f de c5 4a }
    $pattern_38 = { ad 49 a2 ?? ?? ?? ?? 4c e1 5b 8b 1c 87 }
    $pattern_39 = { 34 00 b6 87 bc 08 3c 00 cd 87 ce 08 34 00 }

  condition:
    7 of them and filesize < 3834880
}