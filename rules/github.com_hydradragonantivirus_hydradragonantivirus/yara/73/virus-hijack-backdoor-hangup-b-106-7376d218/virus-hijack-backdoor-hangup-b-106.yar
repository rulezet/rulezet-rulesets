rule Virus_Hijack_Backdoor_Hangup_B_106 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_106.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "296b41815edabae162c7b13b30b5c87c53e95511f53c9b695737c9b92fbbc178"

  strings:
    $s1 = "WOthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}