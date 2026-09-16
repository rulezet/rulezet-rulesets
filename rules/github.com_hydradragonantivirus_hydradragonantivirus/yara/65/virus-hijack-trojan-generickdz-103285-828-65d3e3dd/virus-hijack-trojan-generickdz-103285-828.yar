rule Virus_Hijack_Trojan_GenericKDZ_103285_828 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_828.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6100e83eb51c8fb023decc56e7fe678b26c8faa2f759b9a383201114bcd7d107"

  strings:
    $s1 = "\" HARr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}