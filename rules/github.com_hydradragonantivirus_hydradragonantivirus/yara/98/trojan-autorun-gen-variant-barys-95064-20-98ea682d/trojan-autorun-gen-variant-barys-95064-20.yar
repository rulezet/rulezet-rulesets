rule Trojan_Autorun_Gen_Variant_Barys_95064_20 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7675326532e40642f9b6705d070abb862d4d8388ca3d9de6cea860066719b123"

  strings:
    $s1 = "]QUOp}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}