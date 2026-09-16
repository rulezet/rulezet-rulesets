rule Virus_Hijack_Trojan_GenericKDZ_74550_184_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_184_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "846494b6e3b536f71ff762b74b325069df632f404df3ff614c13b049918f05a7"

  strings:
    $s1 = "CeIL$4K>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}