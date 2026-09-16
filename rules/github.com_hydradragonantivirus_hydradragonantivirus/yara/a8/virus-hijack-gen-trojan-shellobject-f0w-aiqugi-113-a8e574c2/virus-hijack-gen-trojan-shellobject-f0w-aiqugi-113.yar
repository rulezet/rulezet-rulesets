rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_113 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_113.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa22b115135d0aa9b6512e082a10cd022c5babe6c7a2cd1a38b4898e4c76361e"

  strings:
    $s1 = "K4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}