rule Virus_Hijack_Trojan_GenericKDZ_98113_392_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_392_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c8af1ad5c72b334ec107553de04ddd0a10ff74540fc66f892b5e33d5b54eb0a"

  strings:
    $s1 = "v!eGoL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}