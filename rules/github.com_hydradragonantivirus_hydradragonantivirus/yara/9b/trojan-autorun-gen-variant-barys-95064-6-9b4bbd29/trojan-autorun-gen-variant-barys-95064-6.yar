rule Trojan_Autorun_Gen_Variant_Barys_95064_6 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90e7ed77771e1efd406525ef29d99e73e62a97791f49939b4d668198f29b7cc7"

  strings:
    $s1 = "`X@]hazY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}