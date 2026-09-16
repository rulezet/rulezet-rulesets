rule Trojan_Autorun_Trojan_GenericKD_66110182_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.66110182_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "298739bf937ec1c6752992dea0e755ad505e3118d77b16638b130ae7e8aa20ad"

  strings:
    $s1 = ",dOBy@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}