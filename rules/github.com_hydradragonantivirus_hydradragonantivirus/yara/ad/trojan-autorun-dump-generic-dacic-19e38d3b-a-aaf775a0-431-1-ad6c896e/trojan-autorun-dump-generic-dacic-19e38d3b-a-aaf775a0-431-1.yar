rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_431_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_431_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1044d29751f8599127ab446d8667a67bd887eb35d5c9c1ada0d9d0a18e84a7c1"

  strings:
    $s1 = "Bgzean3$weka`+|k`yzgf+Yq~g?Jsfz" fullword ascii
    $s2 = "Bgzean3$weka`+fkgy?GD]-$:82`{lvp2hp`w+pj2i~gy+pb2h~vv\"!a&:w" fullword ascii
    $s3 = "<r~l}d1g}fswire{g1ngep*qdr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}