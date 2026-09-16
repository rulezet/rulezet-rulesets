import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_17_2_Virus_Hija_428 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_17_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17d79876b6187a685a125dae7d1b95a5ba8556544190d3baad49383d1db0610c"
    hash2       = "024ed6b2ab41042a49490b82e8cdc5a221e4881aba86391c265b5c78e8d53ac5"

  strings:
    $s1 = "<description>HP Update scheduler</description> " fullword ascii
    $s2 = "software\\Hewlett-Packard\\HP Software Update" fullword ascii
    $s3 = "Copyright (C) Hewlett-Packard 2007" fullword wide
    $s4 = "hpwuSchd Application" fullword wide
    $s5 = " hpwuSchd Application" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "be0521b5f306fdd2d0e083a3437532cd" and (all of them)
    ) or (all of them)
}