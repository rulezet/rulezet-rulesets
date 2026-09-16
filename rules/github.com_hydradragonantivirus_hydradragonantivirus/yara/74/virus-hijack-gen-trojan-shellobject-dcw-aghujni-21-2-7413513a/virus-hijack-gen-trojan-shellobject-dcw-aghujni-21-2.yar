rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_21_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_21_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5e0eaeb7e63847a2c85c77689094b4fec43bd6a25533a511e6e14c71a71d97a"

  strings:
    $s1 = "p$VAnG(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}