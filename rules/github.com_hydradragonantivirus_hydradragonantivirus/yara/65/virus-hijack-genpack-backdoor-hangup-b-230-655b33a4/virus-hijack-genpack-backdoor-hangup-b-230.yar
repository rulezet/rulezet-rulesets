rule Virus_Hijack_GenPack_Backdoor_Hangup_B_230 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_230.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea9d29134a0ed0acb2b760db238c81dc11860846ec633461b4ccccf33348966b"

  strings:
    $s1 = "_]the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}