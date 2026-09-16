rule Virus_Hijack_GenPack_Backdoor_Hangup_B_217 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_217.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b643c006ed78bda46b449ec5859e65aa11cbdf7b368f6c2eb52da22f9a1ce19"

  strings:
    $s1 = "6the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}