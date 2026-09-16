rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_351_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_351_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f366999c208908d3ab4368923482a73d9a48d3e0965112163d2a366d9c0b2c8"

  strings:
    $s1 = "i|p]fviH*guH*goLd`|N~zrC$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}