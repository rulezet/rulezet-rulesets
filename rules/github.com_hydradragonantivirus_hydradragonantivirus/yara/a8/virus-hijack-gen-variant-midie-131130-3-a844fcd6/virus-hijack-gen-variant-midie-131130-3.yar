rule Virus_Hijack_Gen_Variant_Midie_131130_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Midie.131130_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289bfe16a84ff6155d70a591ba636148b355671bad0f6d2d9a593f1c273bf5ce"

  strings:
    $s1 = "ramiferous" fullword wide
    $s2 = "Tattooment" fullword wide
    $s3 = "Gnathonize" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}