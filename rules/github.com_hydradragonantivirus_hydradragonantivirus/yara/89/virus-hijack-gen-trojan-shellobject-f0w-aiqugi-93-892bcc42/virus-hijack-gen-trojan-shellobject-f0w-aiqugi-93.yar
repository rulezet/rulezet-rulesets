rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_93 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_93.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cb40013ae9c28627ca128865e05b8941a7fe4e4c9db1d0c133aaf23e05c45ab"

  strings:
    $s1 = "oO4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}