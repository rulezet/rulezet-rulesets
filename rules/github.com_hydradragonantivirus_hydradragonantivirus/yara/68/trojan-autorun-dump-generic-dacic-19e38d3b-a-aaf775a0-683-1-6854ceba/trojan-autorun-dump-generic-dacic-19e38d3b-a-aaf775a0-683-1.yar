rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_683_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_683_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12b623c461a9149eea71766f28542ad89f4d97e84095aaea03fa745d4cff696e"

  strings:
    $s1 = "XMicrosoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}