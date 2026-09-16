rule Virus_Hijack_Trojan_GenericKDZ_98388_98_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_98_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c08dc73cffcfea4e2c51870697066075608bbecbb32e57827363f0b646da0c0"

  strings:
    $s1 = "?Puke>+" fullword ascii
    $s2 = "u,}GAVe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}