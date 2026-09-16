rule Trojan_Danger_Gen_Variant_Ransom_Babuk_86_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Babuk.86_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee97e2397af40d9bac7435a2d048dc9c1def462061fa0c14a39f5f0693aebd44"

  strings:
    $s1 = "'that party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}