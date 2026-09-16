rule Trojan_Autorun_Trojan_GenericKD_72517131_71_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_71_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6529cf73bc4bc586f0b9db900bab06a4646b2917232aa692213630a9690f94e7"

  strings:
    $s1 = "s4TM*B,CZAR(CZ.Cg{f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}