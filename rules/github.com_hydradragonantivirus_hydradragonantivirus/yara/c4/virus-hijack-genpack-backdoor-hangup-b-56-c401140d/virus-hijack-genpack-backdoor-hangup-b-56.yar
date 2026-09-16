rule Virus_Hijack_GenPack_Backdoor_Hangup_B_56 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_56.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2f6f2c9ea5a1375260a21d0ae4fb8ab5a44b7adb494ebcdb24d1f509efbfe34"

  strings:
    $s1 = ">Fthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}