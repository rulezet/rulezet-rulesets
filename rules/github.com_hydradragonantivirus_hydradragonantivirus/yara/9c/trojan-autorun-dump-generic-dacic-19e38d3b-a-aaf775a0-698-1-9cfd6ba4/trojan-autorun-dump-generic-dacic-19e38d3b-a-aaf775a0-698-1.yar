rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_698_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_698_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8db58f2769a62dc48ffe726bf4a19566298d44aa25cf9ece30c042430dfebd02"

  strings:
    $s1 = "Oracle does not warrant that the Oracle Universi" fullword ascii
    $s2 = "Microsoft products. You agree that w`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}