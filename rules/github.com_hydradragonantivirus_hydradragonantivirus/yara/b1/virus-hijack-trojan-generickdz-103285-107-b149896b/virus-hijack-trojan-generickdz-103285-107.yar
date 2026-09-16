rule Virus_Hijack_Trojan_GenericKDZ_103285_107 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_107.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "890bca9e9cd6c91b02c2f506f554150730b9d62fd7f05da288235185fc431b4d"

  strings:
    $s1 = "If you choose not to renew the membership, all rights to use the Pre`" fullword ascii
    $s2 = "*a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}