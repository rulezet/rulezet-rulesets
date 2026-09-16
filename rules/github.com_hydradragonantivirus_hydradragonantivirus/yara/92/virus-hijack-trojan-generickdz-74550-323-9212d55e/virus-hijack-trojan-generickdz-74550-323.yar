rule Virus_Hijack_Trojan_GenericKDZ_74550_323 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_323.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "155cc895be3800d71843cc99bbbbba2a7238e2f2da32cd9cfe0e65b9b6566b00"

  strings:
    $s1 = "Lata(V4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}