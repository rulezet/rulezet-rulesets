rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ae0D4Vj_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac573c58480878a191553107893071e5e1bbf005fde7cf5cc3903da2f800fe3"

  strings:
    $s1 = "Ha neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}