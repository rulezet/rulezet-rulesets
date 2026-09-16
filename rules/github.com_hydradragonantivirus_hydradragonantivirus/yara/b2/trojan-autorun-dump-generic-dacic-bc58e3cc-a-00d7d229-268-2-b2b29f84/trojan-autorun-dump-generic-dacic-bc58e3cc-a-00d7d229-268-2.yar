rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_268_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_268_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "532d29ffd58328de7ea120f00c02bb60955a4d47cb4ed89498c727c83344ab22"

  strings:
    $s1 = "|[SWat" fullword ascii
    $s2 = "@brOG&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}