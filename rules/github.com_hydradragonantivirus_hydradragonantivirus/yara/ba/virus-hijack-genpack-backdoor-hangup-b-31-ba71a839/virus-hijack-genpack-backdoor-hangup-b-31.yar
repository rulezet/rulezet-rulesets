rule Virus_Hijack_GenPack_Backdoor_Hangup_B_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ffc5e83d474adbe0f6b654bd203d8e8d43a409e13dc3bfaebc3ff9173791042"

  strings:
    $s1 = "Lthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}