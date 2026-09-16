rule Virus_Hijack_Gen_Trojan_ShellObject_n9Z_aO3hPGn_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n9Z@aO3hPGn_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cab2b3290e7c245afc173a7995e356c0e6f54bf39fb5f49c419d4b5556b3f355"

  strings:
    $s1 = "A)3*YuFt:g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}