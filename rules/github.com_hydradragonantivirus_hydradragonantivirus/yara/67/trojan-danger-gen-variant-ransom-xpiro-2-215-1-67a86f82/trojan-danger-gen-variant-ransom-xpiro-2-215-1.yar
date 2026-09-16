rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_215_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_215_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a8431ead1ae5f254d6a48dd64c39b9dd60f8633eb671ed09c3a5c1a64a9356"

  strings:
    $s1 = "24Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}