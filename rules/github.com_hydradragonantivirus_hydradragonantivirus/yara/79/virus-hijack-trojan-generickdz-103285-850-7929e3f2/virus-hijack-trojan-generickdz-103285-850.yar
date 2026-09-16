rule Virus_Hijack_Trojan_GenericKDZ_103285_850 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_850.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f01adb36872c0348d307eb6421384d21655d75cecd7b4222949149347bdc0a40"

  strings:
    $s1 = "wQa neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}