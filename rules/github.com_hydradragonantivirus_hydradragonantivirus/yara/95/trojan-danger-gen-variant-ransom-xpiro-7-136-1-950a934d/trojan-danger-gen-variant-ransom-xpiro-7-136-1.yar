rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_136_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_136_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86086fdc3fd6803d400614767c345b8b78e19e770be248410aaf94e369c9f855"

  strings:
    $s1 = "0Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii
    $s2 = ";PeNSy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}