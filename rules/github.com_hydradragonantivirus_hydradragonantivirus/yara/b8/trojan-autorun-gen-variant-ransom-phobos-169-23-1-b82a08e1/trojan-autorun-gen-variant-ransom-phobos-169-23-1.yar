rule Trojan_Autorun_Gen_Variant_Ransom_Phobos_169_23_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "886420ddc40653834e6b49ca4fc2975417bf2cf37b616a8b7dc7f26a09e259ec"

  strings:
    $s1 = "Y4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}