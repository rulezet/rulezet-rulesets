rule Virus_Hijack_Trojan_GenericKDZ_99416_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fbd87b7c7cc5b64c0eee2d2e931af64f85671fa7fb975cac89f112c3125df86"

  strings:
    $s1 = "Duel[%\"" fullword ascii
    $s2 = "JuCk$l" fullword ascii
    $s3 = "LIMU(7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}