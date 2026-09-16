rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68baf9b51ce3758d69bd70d6c05503e73ea6197477044429ff883083f32e2ea4"

  strings:
    $s1 = "7{fEoD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}