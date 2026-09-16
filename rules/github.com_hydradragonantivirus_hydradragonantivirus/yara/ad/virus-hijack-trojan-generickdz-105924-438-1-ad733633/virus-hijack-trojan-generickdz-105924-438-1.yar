rule Virus_Hijack_Trojan_GenericKDZ_105924_438_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_438_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea501022349c46bb5e601a62b15e7da196669b504783f1f29b1de4eea58c8d63"

  strings:
    $s1 = "pApa'M" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}