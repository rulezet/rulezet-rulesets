rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_84 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_84.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69018b9bfa4ce0d2751715751e714c1bb3a32a508d4378b3ad617642c655258"

  strings:
    $s1 = "RoRY}tkihkedYR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}