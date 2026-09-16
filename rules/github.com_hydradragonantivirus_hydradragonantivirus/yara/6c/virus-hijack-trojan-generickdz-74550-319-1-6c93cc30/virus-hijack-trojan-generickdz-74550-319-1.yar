rule Virus_Hijack_Trojan_GenericKDZ_74550_319_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_319_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b33f5e6794dd3e1e04a19583e006dd10809d449179b5c456143ee82ece0d660"

  strings:
    $s1 = "GUSs#fB" fullword ascii
    $s2 = "Wilk> " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}