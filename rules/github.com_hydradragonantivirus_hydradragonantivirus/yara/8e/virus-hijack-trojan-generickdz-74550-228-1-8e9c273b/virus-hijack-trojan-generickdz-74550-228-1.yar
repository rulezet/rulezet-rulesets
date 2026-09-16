rule Virus_Hijack_Trojan_GenericKDZ_74550_228_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_228_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "705d799eef91bbc26025478b034b7592d3eb0791e090a1dbe7ab45026fa5ef3a"

  strings:
    $s1 = "AriD)kD" fullword ascii
    $s2 = ">Eyne(d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}