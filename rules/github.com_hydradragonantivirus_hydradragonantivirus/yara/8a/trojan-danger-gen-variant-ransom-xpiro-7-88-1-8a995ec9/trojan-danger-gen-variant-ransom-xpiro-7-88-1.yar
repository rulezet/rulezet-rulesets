rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_88_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_88_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64d786124cdf634574365b70b27930ccb8df7e1620711fc8f2f448fd01f2f7ff"

  strings:
    $s1 = "&purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}