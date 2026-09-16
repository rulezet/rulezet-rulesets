rule Virus_Hijack_Backdoor_Hangup_B_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53591cb48feed8aeb454bada1f9a2a7ade93e6c69051386805aa7b797c1266d1"

  strings:
    $s1 = "[lthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}