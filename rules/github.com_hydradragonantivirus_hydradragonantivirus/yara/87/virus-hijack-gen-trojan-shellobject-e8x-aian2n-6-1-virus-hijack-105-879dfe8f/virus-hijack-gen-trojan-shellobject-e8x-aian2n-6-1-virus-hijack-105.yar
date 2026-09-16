import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_6_1_Virus_Hijack_105 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.E8Z@a41ciQg_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.E8Z@a41ciQg_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.E8Z@a41ciQg_16.vir, Virus.Hijack_Gen.Trojan.ShellObject.E8Z@a41ciQg_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24e61fac48e1e532432ac1994a0171b70b0ec5c30b45490d3c28fbb2145b173e"
    hash2       = "ab0ff5860b4b59ac529ae2d270cfc99238d640ab4e7e5baa881ca8c830768404"
    hash3       = "3c5997c3434fd6d594812071b6a57b5a790489ecd1330176ed709fdf510eb9ff"
    hash4       = "a5af0752e064050d25237507bdce26bf607a7dd8fa9e887e646189a016e95dfc"
    hash5       = "a87811c2ffb4cf23d7f1b274627df9fa4037e3c7c7cc492c41dd8216cfa4972e"
    hash6       = "4c7fe010ce342190b203f7f8b72ca3f51c83eca015447376d5ddb89d3c4c3c4d"
    hash7       = "7d5139da0afe92e4dd65591fa7ebcf30ec2e4bd8b78e4a2a8f392dd30fffc14f"
    hash8       = "02f5f684921e82c981198b020e896046147533b434c2979cd3af6e51e7436d14"

  strings:
    $s1 = "Find CPU Error" fullword ascii
    $s2 = "%s \"%s\",Dispatch" fullword ascii
    $s3 = "cracked by ximo" fullword ascii
    $s4 = "cracked by ximos" fullword ascii
    $s5 = "cracked by ximo-u}" fullword ascii
    $s6 = "cracked by ximo;" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "eb8ce8d6456329b7038389384482d394" and (all of them)
    ) or (all of them)
}