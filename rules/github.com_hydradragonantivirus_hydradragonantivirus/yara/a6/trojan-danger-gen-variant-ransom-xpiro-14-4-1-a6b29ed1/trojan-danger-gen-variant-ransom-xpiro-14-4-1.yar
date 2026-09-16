rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9740a43139195d032fcabd428d74cc59c2f8f6869ca3d05f4619faf8b19de31c"

  strings:
    $s1 = "E|Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}