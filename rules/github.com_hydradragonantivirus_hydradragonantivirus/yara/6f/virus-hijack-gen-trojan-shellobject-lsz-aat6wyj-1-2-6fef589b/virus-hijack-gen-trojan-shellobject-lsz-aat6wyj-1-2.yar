rule Virus_Hijack_Gen_Trojan_ShellObject_lSZ_aaT6Wyj_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.lSZ@aaT6Wyj_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb353d2be9de6f5cd0f42665e968f1f10ac0a5e0b8186011ba56d21f66e705dc"

  strings:
    $s1 = "\\\"jOUk" fullword ascii
    $s2 = "[\"jOUk" fullword ascii
    $s3 = "Y\"jOUk" fullword ascii
    $s4 = "X\"jOUk" fullword ascii
    $s5 = "Z\"jOUk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}