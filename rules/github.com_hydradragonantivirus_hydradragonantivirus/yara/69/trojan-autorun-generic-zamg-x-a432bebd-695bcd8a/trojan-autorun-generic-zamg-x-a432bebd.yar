rule Trojan_Autorun_Generic_Zamg_X_A432BEBD {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Zamg.X.A432BEBD.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92f9c49834870bdfd2d460c5abcc8da11fb4a65434dbfdec3f5aa07d3d0fcb0e"

  strings:
    $s1 = "BinO,V<i=o*" fullword ascii
    $s2 = "This pr9og" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}