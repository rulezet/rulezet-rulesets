rule Virus_Hijack_Trojan_GenericKDZ_103285_881_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_881_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05d8577b7a2f5011bc3bd3a16a692a341f996696a69e33517b75456aaf020eeb"

  strings:
    $s1 = "hEAL!x7" fullword ascii
    $s2 = "rImy)W" fullword ascii
    $s3 = "Slap$}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}