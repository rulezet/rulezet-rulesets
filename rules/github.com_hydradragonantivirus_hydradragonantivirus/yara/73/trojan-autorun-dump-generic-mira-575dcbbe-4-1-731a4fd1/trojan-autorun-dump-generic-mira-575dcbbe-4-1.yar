rule Trojan_Autorun_Dump_Generic_Mira_575DCBBE_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Mira.575DCBBE_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baa9528f7bf98ae9b95ea13faaa4cfaf54efde3e3ff6857087936f37b6a83599"

  strings:
    $s1 = "F\\the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}