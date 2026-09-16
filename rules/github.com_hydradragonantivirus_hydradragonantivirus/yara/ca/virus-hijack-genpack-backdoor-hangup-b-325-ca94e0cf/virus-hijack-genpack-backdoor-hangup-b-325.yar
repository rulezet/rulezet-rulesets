rule Virus_Hijack_GenPack_Backdoor_Hangup_B_325 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_325.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc81ad3d19a074f1003a3b614fe2e649d8ce1afc57b6d503075253a3f72e8146"

  strings:
    $s1 = "/[the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}