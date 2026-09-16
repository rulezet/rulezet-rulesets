rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_15_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f89b094c8b5bdf67f7ae0b0db26c3fd14e4cd0a3dae6ecd36e4568899992b707"

  strings:
    $s1 = "Copyright SysProfd 2018" fullword wide
    $s2 = "TOmE(2H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}