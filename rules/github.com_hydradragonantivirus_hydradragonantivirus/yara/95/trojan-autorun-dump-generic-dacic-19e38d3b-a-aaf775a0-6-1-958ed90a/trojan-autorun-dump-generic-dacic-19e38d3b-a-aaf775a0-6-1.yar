rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dd72c9650c97852de868b9581be98efc898b38c1dd2d47cc8adfb734a273b7b"

  strings:
    $s1 = "DuaD)%70j!}]Dlz" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}