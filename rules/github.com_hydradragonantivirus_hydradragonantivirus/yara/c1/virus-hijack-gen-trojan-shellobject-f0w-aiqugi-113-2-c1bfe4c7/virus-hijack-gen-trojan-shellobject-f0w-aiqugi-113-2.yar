rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_113_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_113_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74fff5117ad93ab456b6d95bc55d481ba6f2ec5791ce852796e0ad37dc504e18"

  strings:
    $s1 = "6!erTH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}