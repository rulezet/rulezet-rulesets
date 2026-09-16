rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_113_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_113_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef8e6fbfa4e6d54d322aa687b1bc7965e369452db3e2bf492c116d777b14d9e1"

  strings:
    $s1 = ".Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}