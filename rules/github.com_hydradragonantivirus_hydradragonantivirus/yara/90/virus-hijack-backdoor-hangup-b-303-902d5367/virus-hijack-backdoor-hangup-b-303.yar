rule Virus_Hijack_Backdoor_Hangup_B_303 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_303.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08bce2d38f6e986008c732a0c29afc74e6c9c4aef0cde107b53d4e5dbf0219b5"

  strings:
    $s1 = "$6the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}