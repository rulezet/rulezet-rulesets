rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5d28049c60e43f7479982dc9dcb741594195829f2ad62589884d39d392234f1"

  strings:
    $s1 = ",IUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}