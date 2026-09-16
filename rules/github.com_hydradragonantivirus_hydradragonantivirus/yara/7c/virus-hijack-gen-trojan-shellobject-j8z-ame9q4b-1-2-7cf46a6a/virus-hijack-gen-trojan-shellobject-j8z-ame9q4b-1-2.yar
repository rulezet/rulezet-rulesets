rule Virus_Hijack_Gen_Trojan_ShellObject_J8Z_ame9q4b_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.J8Z@ame9q4b_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95faf6510adf023943c04e86b148073972ffcc6507b7692a419816919d163116"

  strings:
    $s1 = "<[yAyA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}