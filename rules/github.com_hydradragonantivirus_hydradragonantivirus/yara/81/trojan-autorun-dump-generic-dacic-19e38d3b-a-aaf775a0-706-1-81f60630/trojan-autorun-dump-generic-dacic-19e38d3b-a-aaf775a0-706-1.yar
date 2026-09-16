rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_706_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_706_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca417ceeffeb3a6190d9244cbcc9697b9427f94ed5c2638b60f082ab6469cc9b"

  strings:
    $s1 = "#bare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}