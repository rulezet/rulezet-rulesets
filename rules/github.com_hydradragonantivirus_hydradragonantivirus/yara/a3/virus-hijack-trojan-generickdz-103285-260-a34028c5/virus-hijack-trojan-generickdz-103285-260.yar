rule Virus_Hijack_Trojan_GenericKDZ_103285_260 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_260.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ea1b94bc232353c975c8a8e3f01934d772efdeee5429f73568e0e900af6755f"

  strings:
    $s1 = "o7microsoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}