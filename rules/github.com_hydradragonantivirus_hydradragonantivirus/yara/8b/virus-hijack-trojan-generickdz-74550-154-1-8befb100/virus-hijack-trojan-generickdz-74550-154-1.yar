rule Virus_Hijack_Trojan_GenericKDZ_74550_154_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_154_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8f7075d4e3c7a6be7a42402c7b892ea97fb7f7443e96aec0a985671581c6a4a"

  strings:
    $s1 = "VULn (K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}