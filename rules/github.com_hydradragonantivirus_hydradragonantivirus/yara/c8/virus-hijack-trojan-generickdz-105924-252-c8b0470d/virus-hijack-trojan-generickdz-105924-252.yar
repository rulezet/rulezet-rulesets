rule Virus_Hijack_Trojan_GenericKDZ_105924_252 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_252.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9af4709076fb995f95e1b8cbed2120884d3287a1bff04c32067632a213cfcd8"

  strings:
    $s1 = "!]lOKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}