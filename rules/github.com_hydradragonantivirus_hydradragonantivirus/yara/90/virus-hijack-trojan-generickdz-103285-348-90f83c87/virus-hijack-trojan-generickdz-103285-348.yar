rule Virus_Hijack_Trojan_GenericKDZ_103285_348 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_348.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7a3e0af128f4ed018721bb47112a2f33fba5b1af59fef735f58f196a66cbaa3"

  strings:
    $s1 = "What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}