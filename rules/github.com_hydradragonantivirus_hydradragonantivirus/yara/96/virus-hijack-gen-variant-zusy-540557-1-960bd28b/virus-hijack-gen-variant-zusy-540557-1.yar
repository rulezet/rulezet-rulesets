rule Virus_Hijack_Gen_Variant_Zusy_540557_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zusy.540557_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51616571c90cf270fd2e0c189788773134d44bf501fb2d1aa595dfe57207a93c"

  strings:
    $s1 = "LIte&T4" fullword ascii
    $s2 = "PUky[HJ" fullword ascii
    $s3 = "#qsD:Homo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}