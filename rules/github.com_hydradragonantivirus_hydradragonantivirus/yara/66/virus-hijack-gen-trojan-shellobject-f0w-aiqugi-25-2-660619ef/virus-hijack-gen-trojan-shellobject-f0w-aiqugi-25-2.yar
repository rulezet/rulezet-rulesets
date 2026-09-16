rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_25_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_25_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6e76e326d39cbe942d69f7d27cfa23355ddeb710a1ab7a29515cf0a001ce1b8"

  strings:
    $s1 = "ALga;Of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}