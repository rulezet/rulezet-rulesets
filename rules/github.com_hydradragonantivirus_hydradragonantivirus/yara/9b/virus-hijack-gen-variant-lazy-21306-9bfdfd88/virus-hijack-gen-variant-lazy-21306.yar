rule Virus_Hijack_Gen_Variant_Lazy_21306 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Lazy.21306.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "561ee7b30c6ce22607cb0da48792c052f4bd427a3600aa902e9276e5bade81a9"

  strings:
    $s1 = "AntiVir Command Line Scanner for Windows" fullword wide
    $s2 = " 2007 Avira GmbH. All rights reserved." fullword wide
    $s3 = " is a registered trademark of Avira GmbH, Germany" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}