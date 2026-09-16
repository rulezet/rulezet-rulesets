rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_91 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_91.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "361032ca2d6309f1fce450231216a1647f60fea32678ee9498bb2f411075d4e2"

  strings:
    $s1 = "~K4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}