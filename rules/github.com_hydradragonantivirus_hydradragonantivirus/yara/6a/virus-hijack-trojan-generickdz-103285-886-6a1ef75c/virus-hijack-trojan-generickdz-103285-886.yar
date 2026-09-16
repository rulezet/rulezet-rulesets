rule Virus_Hijack_Trojan_GenericKDZ_103285_886 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_886.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8a3439763234e773ab5be24df2b77da1e9d0bab98323af6b44863fc646ee8e8"

  strings:
    $s1 = "LUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}