rule Virus_Hijack_Trojan_GenericKDZ_103285_51 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_51.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe05e9522940de1633efe4e8d8bef68d590fb3e512c6bdfbed3534d4d09a9a4f"

  strings:
    $s1 = "!Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}