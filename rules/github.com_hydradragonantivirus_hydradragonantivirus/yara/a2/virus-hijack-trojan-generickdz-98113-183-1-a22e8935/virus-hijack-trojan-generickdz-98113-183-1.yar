rule Virus_Hijack_Trojan_GenericKDZ_98113_183_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_183_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9948d4818b791e7c021a276e50c17d5a8c392df64e4bdf06573473c878090bfd"

  strings:
    $s1 = "F CrOY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}