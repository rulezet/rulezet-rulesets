rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_37_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_37_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f0d964fe9b114e9263ed3a69b0b83f96c8bd67bab6e55db8612affd66f937f0"

  strings:
    $s1 = "p$VAnG(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}