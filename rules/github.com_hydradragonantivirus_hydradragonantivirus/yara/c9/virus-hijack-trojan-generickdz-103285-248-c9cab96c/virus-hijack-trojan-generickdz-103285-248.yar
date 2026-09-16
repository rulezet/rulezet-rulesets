rule Virus_Hijack_Trojan_GenericKDZ_103285_248 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_248.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3a8d44865cd835cf48d3da255da05e9d518189bc6ee26071874ab55679d1c49"

  strings:
    $s1 = "If you choose not to renew the membership, all rights to use the Pre`" fullword ascii
    $s2 = "@!a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}