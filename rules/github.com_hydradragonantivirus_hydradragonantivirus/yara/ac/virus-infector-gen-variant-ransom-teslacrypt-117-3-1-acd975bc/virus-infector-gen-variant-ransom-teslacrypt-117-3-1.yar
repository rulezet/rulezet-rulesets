rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_117_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.117_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dadb0ebb01290c3571acc241e33c4ba56fd63c147d8836be9ca35d0aab6852a"

  strings:
    $s1 = "g Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference Viewi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}