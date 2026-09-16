rule Virus_Hijack_GenPack_Backdoor_Hangup_B_353 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_353.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c644af04238ac8f7990437e54135f8f539acbb4ea4621036d882b02000bd591"

  strings:
    $s1 = "Xthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}