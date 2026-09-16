rule Virus_Hijack_Trojan_GenericKDZ_105924_172_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_172_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c844776fcda16bda4a465da4b36cc78c2b2402f9d7480314c73afce9e87b1f4"

  strings:
    $s1 = "PHYSICAL;DR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}