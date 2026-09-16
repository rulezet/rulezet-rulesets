rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_178_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_178_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ac02692e743d343061c56d75f962687a28e76a7477ee0067f8b976225c94c48"

  strings:
    $s1 = "HiKE!MXhX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}