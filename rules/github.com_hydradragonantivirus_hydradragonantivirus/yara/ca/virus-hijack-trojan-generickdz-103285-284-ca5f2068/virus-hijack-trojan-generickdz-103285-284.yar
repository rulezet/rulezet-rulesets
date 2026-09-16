rule Virus_Hijack_Trojan_GenericKDZ_103285_284 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_284.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2b1786b8b1850f34636f6109efb49ae81fdefcc337da42c162a419840cee356"

  strings:
    $s1 = "b{University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}