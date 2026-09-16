rule Virus_Hijack_Trojan_GenericKDZ_98113_29 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3882b59f227c7a86c11dbf4ca92951e7f778517ff89e982af70b167bedf22b8"

  strings:
    $s1 = "aor service that is subject to a discount or a pr" fullword ascii
    $s2 = "}aSdiC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}