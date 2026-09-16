rule Virus_Hijack_Trojan_GenericKDZ_74550_353_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_353_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "684062bedc24d8e3218636ed3b0a9dc78969a3e909e5c7bf023466901f813d8e"

  strings:
    $s1 = "pE)RiSt" fullword ascii
    $s2 = "gawm<(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}