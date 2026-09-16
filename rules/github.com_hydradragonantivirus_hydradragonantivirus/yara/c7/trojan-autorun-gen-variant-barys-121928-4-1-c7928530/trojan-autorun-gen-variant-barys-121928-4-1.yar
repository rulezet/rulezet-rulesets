rule Trojan_Autorun_Gen_Variant_Barys_121928_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.121928_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d36c4ec2c30910f1ffdb129ee8973a74ce361a01464ce5338b1d8a028a943d7d"

  strings:
    $s1 = "d4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}