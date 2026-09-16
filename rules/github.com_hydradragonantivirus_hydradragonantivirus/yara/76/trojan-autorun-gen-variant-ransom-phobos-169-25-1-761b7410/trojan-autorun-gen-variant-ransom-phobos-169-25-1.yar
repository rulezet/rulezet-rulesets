rule Trojan_Autorun_Gen_Variant_Ransom_Phobos_169_25_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "509e8f36ca53ae93d3365c78774d734ce721e01f1ef6e3da34becf23ac796e15"

  strings:
    $s1 = "3Cby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}