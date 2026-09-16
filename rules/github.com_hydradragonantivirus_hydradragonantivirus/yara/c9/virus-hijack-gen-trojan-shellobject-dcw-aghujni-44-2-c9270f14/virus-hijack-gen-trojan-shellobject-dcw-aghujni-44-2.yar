rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_44_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_44_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "539a83ea29e46dec6ca7c6f17e932259624c2919b1f443463dbf690c027fb1a7"

  strings:
    $s1 = "p$VAnG(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}