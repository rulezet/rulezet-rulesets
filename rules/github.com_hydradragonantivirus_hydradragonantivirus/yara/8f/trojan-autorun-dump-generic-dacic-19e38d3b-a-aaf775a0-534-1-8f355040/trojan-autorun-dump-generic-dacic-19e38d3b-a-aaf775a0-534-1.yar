rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_534_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_534_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92f798ba0199f7e025db4330580aa929476a7c09c8636ebe236005a17949a84a"

  strings:
    $s1 = "O(loOm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}