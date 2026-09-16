rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_129_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_129_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b6b18743a89bff4a23b88862b56939f8af0aad4706fb090b58ae275a165d816"

  strings:
    $s1 = "\\<waLT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}