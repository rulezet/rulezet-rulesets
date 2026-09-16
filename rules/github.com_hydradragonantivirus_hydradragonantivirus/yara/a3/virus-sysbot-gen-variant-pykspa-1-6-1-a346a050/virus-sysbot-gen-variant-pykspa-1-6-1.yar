rule Virus_Sysbot_Gen_Variant_Pykspa_1_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Variant.Pykspa.1_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cd6cacd7603ad3206194941e2b68f3d20affc5b9cc96e8d0220cafd7ed9e3ae"

  strings:
    $s1 = "C?luCy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}