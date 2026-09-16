rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_332_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_332_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62cf608971b899d9e65846f1bd3ba001cf6f884e11bee2a3b58434fbfc261e8d"

  strings:
    $s1 = "@~~@Java Machine@~~@1@~~@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}