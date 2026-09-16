rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_134_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_134_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6de27eccba3d029eec79d201e8b2129ea555c80115390f0a97324e0d86f4b605"

  strings:
    $s1 = "?yOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}