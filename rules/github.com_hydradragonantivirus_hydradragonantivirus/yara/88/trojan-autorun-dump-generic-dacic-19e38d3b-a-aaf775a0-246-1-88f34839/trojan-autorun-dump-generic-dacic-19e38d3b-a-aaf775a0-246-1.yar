rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_246_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_246_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab8773e2e944334e1059512496881f3e501a9d8fb831980041ec1a14037b1efe"

  strings:
    $s1 = "]posted a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}