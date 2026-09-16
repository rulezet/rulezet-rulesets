rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_485_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_485_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4766c1993fd34e7cd518b4324b4d4bfec7a89d2725e0b9d5dad19684be8c4de9"

  strings:
    $s1 = "lOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}