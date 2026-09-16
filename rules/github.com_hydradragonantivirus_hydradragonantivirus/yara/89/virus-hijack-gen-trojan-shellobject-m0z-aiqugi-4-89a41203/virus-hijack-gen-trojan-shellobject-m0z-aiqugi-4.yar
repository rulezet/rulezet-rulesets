rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d8d909ccc967473a1347a0eb499344913eaa3f121fa67374dd3708f309c2f31"

  strings:
    $s1 = "v4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}