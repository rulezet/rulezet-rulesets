rule Trojan_Danger_Trojan_GenericKD_67269844_49 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f96c830a0da90cd1147ef48cb0182082d59e10af29b5a33ba743079db84f8c52"

  strings:
    $s1 = "Interactive Ruby.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}