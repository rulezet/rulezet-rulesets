rule TRELLIX_ARC_APT_Acidbox_Ssp_Dll_Module: BACKDOOR FILE {
  meta:
    description    = "Rule to detect the SSP DLL component of AcidBox"
    author         = "Marc Rivero | McAfee ATR Team"
    id             = "ef1511c5-f650-5e65-937c-466f00932183"
    date           = "2020-07-24"
    modified       = "2020-08-14"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_acidbox.yar#L67-L98"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "4c9b9de11d73587ca1ad1efa5455598e41edc5a9a59fc0339c429a212c1c7941"
    score          = 75
    quality        = 70
    tags           = "BACKDOOR, FILE"
    rule_version   = "v1"
    malware_type   = "backdoor"
    malware_family = "Backdoor:W32/Acidbox"
    actor_type     = "APT"
    actor_group    = "Turla"
    hash1          = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"

  strings:
    $pattern_0 = { 49 89 7b a0 8b c7 49 89 43 98 49 89 7b a8 33 c9 49 89 4b b0 }
    $pattern_1 = { 8b 84 24 a8 00 00 00 c1 e8 18 88 44 31 08 66 89 5c 31 0a 49 8b 0e }
    $pattern_2 = { 8b 5f 48 41 3b dd 41 0f 47 dd 85 db 0f 84 f1 00 00 00 48 8b 47 20 48 85 c0 }
    $pattern_3 = { e8 ?? ?? ?? ?? 85 c0 78 c7 48 8d 94 24 a0 02 00 00 48 8d 8c 24 e0 03 00 00 ff 15 ?? ?? ?? ?? 4c 8b f8 }
    $pattern_4 = { ff 15 ?? ?? ?? ?? 48 8b c8 4c 8b c6 33 d2 ff 15 ?? ?? ?? ?? 8b fb 89 5c 24 20 }
    $pattern_5 = { 41 5f c3 4c 8b dc 49 89 5b 10 }
    $pattern_6 = { 48 8d 84 24 88 01 00 00 48 89 44 24 20 41 bf ?? ?? ?? ?? 45 8b cf 4c 8b c7 41 8b d7 48 8d 8c 24 90 00 00 00 }
    $pattern_7 = { c1 e9 08 0f b6 c9 3b ce 77 b6 8b d0 b9 ?? ?? ?? ?? c1 ea 10 }
    $pattern_8 = { 4c 8b c3 ba ?? ?? ?? ?? 48 8d 4c 24 38 e8 ?? ?? ?? ?? 89 44 24 30 85 c0 75 08 }
    $pattern_9 = { bb 02 16 04 80 8b c3 48 8b 5c 24 40 48 8b 74 24 48 48 8b 7c 24 50 48 83 c4 30 }

  condition:
    7 of them and filesize < 199680
}