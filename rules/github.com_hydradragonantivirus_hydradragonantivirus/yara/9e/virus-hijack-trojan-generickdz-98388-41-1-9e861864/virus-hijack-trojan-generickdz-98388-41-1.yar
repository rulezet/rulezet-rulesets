rule Virus_Hijack_Trojan_GenericKDZ_98388_41_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fa5cc3078bc02183473613501c0dc4739d7f6df4ffea5ae75bf1f8bf9e6e034"

  strings:
    $s1 = "u[bLaH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}