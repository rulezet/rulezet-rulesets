rule Virus_Hijack_Trojan_GenericKDZ_98113_150_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_150_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eafb65f5644bc1290af18d3917f98a74f112af5be0b4cd7fc72d5abd43b854ec"

  strings:
    $s1 = "&[TheW" fullword ascii
    $s2 = "[&agIo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}