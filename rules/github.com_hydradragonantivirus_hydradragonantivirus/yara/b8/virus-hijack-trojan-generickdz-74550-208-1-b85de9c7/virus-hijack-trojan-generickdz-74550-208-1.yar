rule Virus_Hijack_Trojan_GenericKDZ_74550_208_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_208_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "837c514f28e7ea4cf72b701a74edf9b0fb25226faa4759fa52802c356eeddad3"

  strings:
    $s1 = "n*Mike" fullword ascii
    $s2 = "6)gYTe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}