rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_66 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_66.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "606fecfc5c7083deb25588c368255170f87141f6747734555177d6c348f0d29f"

  strings:
    $s1 = "BM4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}