rule Virus_Hijack_Trojan_GenericKDZ_103545_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3daf020cc7316437f59a65f9b6c26e02ce83191e785e682774a3a0b0ed3a5cc6"

  strings:
    $s1 = "asoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}