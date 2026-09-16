rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_39 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92ca9a1513b5f959373f464664b3be20bb92bec2747cc2bd3f349ce5766a10ae"

  strings:
    $s1 = "<4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}