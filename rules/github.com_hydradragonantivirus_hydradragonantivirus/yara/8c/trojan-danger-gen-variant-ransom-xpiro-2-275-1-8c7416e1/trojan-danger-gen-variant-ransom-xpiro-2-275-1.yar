rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_275_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_275_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eda3eabd3f6541d3603084dbec85e42997e55aa7974a1ecd5c4fd50d10387cae"

  strings:
    $s1 = "PAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}