rule Virus_Hijack_Trojan_GenericKDZ_103285_142 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_142.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25670e34f59b4d06bdc935ae370bf6a0d7bfb6a5e6d24b18ad4436dfbe00b6e8"

  strings:
    $s1 = "$virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}