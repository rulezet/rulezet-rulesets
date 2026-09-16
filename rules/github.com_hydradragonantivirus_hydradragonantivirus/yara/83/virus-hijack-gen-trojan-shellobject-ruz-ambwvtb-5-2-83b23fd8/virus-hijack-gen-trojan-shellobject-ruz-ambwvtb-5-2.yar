rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "459ca14b5388bed39b4b1330341c3f2ceb5db488ddd6a80c4df782f8916f1eb7"

  strings:
    $s1 = "p@gram J" fullword ascii
    $s2 = "w(null" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}