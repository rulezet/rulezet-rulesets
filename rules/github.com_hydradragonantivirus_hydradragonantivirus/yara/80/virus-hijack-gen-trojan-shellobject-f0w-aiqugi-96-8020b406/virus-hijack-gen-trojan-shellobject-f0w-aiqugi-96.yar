rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_96 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_96.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32cb48477bb768221399fdb7164c8eff39e738d7a79c307f73da7202f8cf4ef8"

  strings:
    $s1 = "Z4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}