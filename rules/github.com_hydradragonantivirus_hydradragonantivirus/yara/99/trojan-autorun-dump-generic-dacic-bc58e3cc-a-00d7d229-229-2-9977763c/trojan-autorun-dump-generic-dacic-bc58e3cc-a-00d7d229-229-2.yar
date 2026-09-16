rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_229_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_229_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc0040743d9a43e41ce7260682b745340ac34f352964e316c42cdc47ce5a5d73"

  strings:
    $s1 = "5@QuIt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}