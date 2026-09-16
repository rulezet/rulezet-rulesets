rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_87_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_87_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccf93f153a66b7d9a7fb2c037713ae0fabd4e93d3377f5474018258bc08631ab"

  strings:
    $s1 = "bpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}