rule Trojan_Autorun_Trojan_GenericKDZ_94847_118_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_118_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b917709c64ec4595c2ddc55449316fbb997db61a6175db5264bb16ee0b0feaf"

  strings:
    $s1 = "'Vwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}