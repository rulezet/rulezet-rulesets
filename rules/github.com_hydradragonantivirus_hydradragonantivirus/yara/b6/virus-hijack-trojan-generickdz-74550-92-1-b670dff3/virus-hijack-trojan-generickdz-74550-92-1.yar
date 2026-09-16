rule Virus_Hijack_Trojan_GenericKDZ_74550_92_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_92_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2a8158adc0ce838edf53768e40e244e285f34cddef91b13a48497ff35a40f9c"

  strings:
    $s1 = "suer)2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}