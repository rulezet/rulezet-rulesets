rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_70_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a01e68fccefb62bea5d5a92a4819033d231be3ed9f617decb1cb58219a9fd5"

  strings:
    $s1 = "RYUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}