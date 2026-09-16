rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_649_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_649_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c2cdf3eedf1d4cd728a675049f056f206e9438bf8ac245d8ceeeb631ad76d93"

  strings:
    $s1 = "must be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}