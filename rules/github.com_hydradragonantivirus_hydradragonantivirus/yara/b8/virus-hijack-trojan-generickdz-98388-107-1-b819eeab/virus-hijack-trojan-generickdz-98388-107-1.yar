rule Virus_Hijack_Trojan_GenericKDZ_98388_107_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_107_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11b79a484ebfdd12c055d8c01fdc104cc77114e3db1799a0a51e9fa320e54870"

  strings:
    $s1 = "CHop&\\" fullword ascii
    $s2 = ",+*>Vuln:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}