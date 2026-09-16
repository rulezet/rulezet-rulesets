rule Virus_Hijack_Trojan_GenericKDZ_105924_311 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_311.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bdc6eb1c43fb89d028e23c817d4fb37ff406b2142a7508090d6a454c52fea91"

  strings:
    $s1 = "U%OdUM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}