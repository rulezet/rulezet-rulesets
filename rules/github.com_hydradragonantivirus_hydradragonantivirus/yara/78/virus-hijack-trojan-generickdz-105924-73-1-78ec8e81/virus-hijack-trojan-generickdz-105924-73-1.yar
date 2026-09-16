rule Virus_Hijack_Trojan_GenericKDZ_105924_73_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_73_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c6eebe302816d369fdcc0c5739a296f7619cb89b4d8a8d57e29f6508192f4e"

  strings:
    $s1 = "AStOny," fullword ascii
    $s2 = "rAnD,lq5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}