rule Virus_Hijack_GenPack_Backdoor_Hangup_B_55 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_55.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dda6de29518c79a26191f2c0ebe9cc9478ee807f86e2a759cdd5cac566357a25"

  strings:
    $s1 = "#the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}