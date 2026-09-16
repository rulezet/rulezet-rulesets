rule Virus_Hijack_Trojan_GenericKDZ_98113_202_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_202_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "064c4b06c1f4bc26c93ae67d4ca7d130233cdeb050a6b5a5d7942118ab8ae5d0"

  strings:
    $s1 = "hL*n[:alIn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}