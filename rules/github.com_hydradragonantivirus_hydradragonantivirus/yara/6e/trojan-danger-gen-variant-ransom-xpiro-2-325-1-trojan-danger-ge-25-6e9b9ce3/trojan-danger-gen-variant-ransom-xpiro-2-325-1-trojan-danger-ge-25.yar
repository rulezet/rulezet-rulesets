rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_325_1_Trojan_Danger_Ge_25 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_325_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_326_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_327_1.vir, Trojan.Injector_Trojan.GenericKD.73245570.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_35_2.vir, Virus.Hijack_Trojan.Agent.DQQO_136_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f7fcf8e0df079666a606145c6ef8bda32df073cccee380b8277a51b3e82a4f9"
    hash2       = "cde8c827b3dfd33aa4213b70df86bca4b02d6aa9856f8db2efe6e8a7e135ce51"
    hash3       = "1cdab97d8a484c05e3323dadc5bc2325e626ee621580fe1375bd659345bbeb12"
    hash4       = "b8b5b339384d04e1ab06dc8e5821030e1a14225af564ddcd75faf84311fcf14e"
    hash5       = "fa6571536176895dc48b1717497eeb6c76b5e24d0d8545ad2559e4718be869ab"
    hash6       = "c9219505f166e2ea9944a792022f1da93980e2915839aa3fbe4b08198c48bd55"

  strings:
    $s1  = "TTL: %d (initial:%d)" fullword wide
    $s2  = "Network: Closed" fullword wide
    $s3  = "Cfailed to open %s" fullword wide
    $s4  = "Incorrect block length" fullword ascii
    $s5  = "Network: Internet" fullword wide
    $s6  = "Time(UTC): %s" fullword wide
    $s7  = "dstdata is NULL" fullword wide
    $s8  = "srcdata is NULL" fullword wide
    $s9  = "Invalid datetime" fullword wide
    $s10 = "Windows Defender Extension" fullword wide
    $s11 = "<o!EVaSE" fullword ascii
    $s12 = "Wna)YATE:" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}