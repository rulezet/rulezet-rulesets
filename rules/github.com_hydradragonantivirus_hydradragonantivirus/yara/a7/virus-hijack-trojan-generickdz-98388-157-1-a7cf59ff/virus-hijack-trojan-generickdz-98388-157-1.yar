rule Virus_Hijack_Trojan_GenericKDZ_98388_157_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_157_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "461617317af1a5e55d05157626d41fafe3d0797f283951ada16bd1093463652b"

  strings:
    $s1 = "R$aBEY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}