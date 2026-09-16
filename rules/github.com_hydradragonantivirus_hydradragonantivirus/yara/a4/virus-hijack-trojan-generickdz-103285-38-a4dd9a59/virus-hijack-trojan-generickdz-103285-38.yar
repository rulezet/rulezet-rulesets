rule Virus_Hijack_Trojan_GenericKDZ_103285_38 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_38.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "910fff58d419486cd3e3a840a89e0b76aad70874b136193cc09b23364ea3c9b4"

  strings:
    $s1 = "X~What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}