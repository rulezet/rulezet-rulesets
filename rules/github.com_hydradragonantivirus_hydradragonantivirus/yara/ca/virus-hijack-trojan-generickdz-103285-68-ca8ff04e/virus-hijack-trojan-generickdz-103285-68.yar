rule Virus_Hijack_Trojan_GenericKDZ_103285_68 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_68.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "081f1b00d147c8ea4d79be4db3e4ec86a6fee3ac179d071746911e6a0bb9dfaf"

  strings:
    $s1 = "y-microsoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}