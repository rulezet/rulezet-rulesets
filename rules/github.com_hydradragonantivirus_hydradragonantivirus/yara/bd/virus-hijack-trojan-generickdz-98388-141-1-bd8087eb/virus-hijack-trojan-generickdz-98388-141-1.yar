rule Virus_Hijack_Trojan_GenericKDZ_98388_141_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_141_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98368fa20db3ccdfd03fb287ca629fcbf0cf2b638a46ed832227be09b5207ca9"

  strings:
    $s1 = "?&Zyme" fullword ascii
    $s2 = "O oOZY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}