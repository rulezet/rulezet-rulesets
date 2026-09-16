rule Virus_Hijack_Trojan_GenericKDZ_103285_847 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_847.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a39661f13b22186337090e1f8b6e3fe1337ce1e487754c4ca79928d7a62575f2"

  strings:
    $s1 = "/policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}