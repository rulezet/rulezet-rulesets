rule Virus_Hijack_Trojan_GenericKDZ_105924_469_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_469_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a19c5c808e10a4c0f99b7ad42df63bbdc0a3c1a127de36500b128c1650b5cdf3"

  strings:
    $s1 = " SLoB;" fullword ascii
    $s2 = "PeAL}." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}