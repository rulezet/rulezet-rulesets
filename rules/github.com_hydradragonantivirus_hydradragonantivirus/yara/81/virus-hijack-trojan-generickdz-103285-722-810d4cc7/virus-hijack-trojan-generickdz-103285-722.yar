rule Virus_Hijack_Trojan_GenericKDZ_103285_722 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_722.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "551c3480db3d2a593deff44a0e5f478c4532b05c340eaae32ffaf6a8c31867ea"

  strings:
    $s1 = "ia neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}