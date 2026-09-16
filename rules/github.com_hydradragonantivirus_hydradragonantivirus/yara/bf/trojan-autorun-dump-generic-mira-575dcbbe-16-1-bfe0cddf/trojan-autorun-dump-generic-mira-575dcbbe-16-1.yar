rule Trojan_Autorun_Dump_Generic_Mira_575DCBBE_16_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Mira.575DCBBE_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9d21aa6384c7bbb3a864e01f45384143ff5325298a0433a2df63f3dba4d7cbf"

  strings:
    $s1 = "Xthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}