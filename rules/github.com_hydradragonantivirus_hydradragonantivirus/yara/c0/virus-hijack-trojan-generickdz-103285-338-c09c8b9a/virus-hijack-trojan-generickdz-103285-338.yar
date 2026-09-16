rule Virus_Hijack_Trojan_GenericKDZ_103285_338 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_338.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9791547b9b4236f80670a94ef4e06b8d5075329c0cc67c6476834d2e61d5f2b3"

  strings:
    $s1 = "v^i[WEt[MEaT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}