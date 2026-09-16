rule Virus_Hijack_Backdoor_Hangup_B_178 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_178.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0d2efa45470c36fb4f3656bcfc1caccd05491785d7f5a68de995a925d8c3f99"

  strings:
    $s1 = "Othe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}