rule Virus_Hijack_Trojan_GenericKDZ_103285_82 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_82.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "983dd157754c2fb2d3f64a28f44ec00ecee9c7bba37e2823228d2177a169efb7"

  strings:
    $s1 = "OWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}