rule Virus_Hijack_Trojan_GenericKDZ_99416_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8765df8dfb5be36f76f02946aba2f6b39a711d0783fdf376b0dccc9aff57c82"

  strings:
    $s1 = "wUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}