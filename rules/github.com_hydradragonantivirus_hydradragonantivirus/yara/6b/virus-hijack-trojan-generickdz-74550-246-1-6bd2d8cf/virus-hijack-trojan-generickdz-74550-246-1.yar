rule Virus_Hijack_Trojan_GenericKDZ_74550_246_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_246_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "695cc20da1ddc87bcbe9184e9ec5ed482f1ed00d3443df4959e10b5e201078ae"

  strings:
    $s1 = "a!TUmp" fullword ascii
    $s2 = "HowE)}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}