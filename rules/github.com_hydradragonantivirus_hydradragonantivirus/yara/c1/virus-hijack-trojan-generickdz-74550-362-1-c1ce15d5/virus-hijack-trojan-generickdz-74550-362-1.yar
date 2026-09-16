rule Virus_Hijack_Trojan_GenericKDZ_74550_362_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_362_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6a59f7c90757ec0688ffa88a5befe728e952b51f415dda94f05d2e5bd1168d2"

  strings:
    $s1 = "\\!GALe" fullword ascii
    $s2 = "rEpp*z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}