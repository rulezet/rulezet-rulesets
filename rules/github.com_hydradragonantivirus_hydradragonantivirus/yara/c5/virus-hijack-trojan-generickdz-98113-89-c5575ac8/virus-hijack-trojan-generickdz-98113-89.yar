rule Virus_Hijack_Trojan_GenericKDZ_98113_89 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_89.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddb92ba43a5a98b74e8217aa1dfa7609946df5a4e925a0416dbbf12c8d199578"

  strings:
    $s1 = "assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}