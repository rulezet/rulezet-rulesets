rule Virus_Hijack_Trojan_GenericKDZ_74550_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ab154e833877e713b8c666823adc5c57340aa0fe15946549de19da197f7c566"

  strings:
    $s1 = "sANk*jn&Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}