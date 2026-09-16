rule Virus_Hijack_Trojan_GenericKDZ_74550_145_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_145_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ef73afe9b9159fa68caa87c648f0f218e6e212a83bf8198f6f8384d74b6fd38"

  strings:
    $s1 = ",[Tall" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}