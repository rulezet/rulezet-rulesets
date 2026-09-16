rule Virus_Hijack_Gen_Variant_Zusy_546584 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zusy.546584.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c3d9dd7df2e4713716627596c06b346522297092f8b7a4e6eb8539260eb7060"

  strings:
    $s1 = "teratogenetic" fullword wide
    $s2 = "clodlet" fullword wide
    $s3 = "Scribblingly" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}