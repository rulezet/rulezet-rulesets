rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_322_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_322_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9c55744938023c75997e10ab02751dc176358ba27b5b76ce37c137e09d7e2ce"

  strings:
    $s1 = ")mOde%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}