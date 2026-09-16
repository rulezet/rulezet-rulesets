rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_100_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_100_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "905d73ae74bdd5306afd913cd3557c8dd26562f243e673f6bd102d23ee8d37b4"

  strings:
    $s1 = "O\\remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}