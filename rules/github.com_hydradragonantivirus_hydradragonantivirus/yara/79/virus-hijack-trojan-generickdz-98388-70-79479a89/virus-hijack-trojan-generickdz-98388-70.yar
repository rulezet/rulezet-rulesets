rule Virus_Hijack_Trojan_GenericKDZ_98388_70 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_70.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b715c0fcda9cf8257a6a0cb919c27c541b8d6cd0071fa9ca1f3fbeeefef813f"

  strings:
    $s1 = "Naze`,}-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}