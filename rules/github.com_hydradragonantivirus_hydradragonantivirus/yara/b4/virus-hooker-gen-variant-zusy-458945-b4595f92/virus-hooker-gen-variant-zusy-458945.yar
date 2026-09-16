rule Virus_Hooker_Gen_Variant_Zusy_458945 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Variant.Zusy.458945.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "230843024f85408ce018cfd8e02a17f45e3a7d9bc2f4240ae223886a9d4ea20e"

  strings:
    $s1 = "Mac Copyright" fullword wide
    $s2 = "Mac Tool" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}