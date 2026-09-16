rule Trojan_Autorun_Trojan_GenericKD_72517131_223_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_223_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d60e66c18baf1b898112842eabd6475d43c43e34fda1a195f2cbab1560ab664"

  strings:
    $s1 = "mfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}