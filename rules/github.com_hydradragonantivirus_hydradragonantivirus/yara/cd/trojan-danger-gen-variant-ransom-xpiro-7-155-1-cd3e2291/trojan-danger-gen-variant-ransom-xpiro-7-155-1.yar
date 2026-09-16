rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_155_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_155_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f7c0473bbbe32d57759589711ef97fe5d4d577369b4f653e39d0508117cd0ee"

  strings:
    $s1 = "lSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}