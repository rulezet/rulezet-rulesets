rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_281_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_281_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e97c7f5e71418cbbfcffe26a9062d53dfabe199957c652cd8eb422f391b0daf"

  strings:
    $s1 = "soDY@P_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}