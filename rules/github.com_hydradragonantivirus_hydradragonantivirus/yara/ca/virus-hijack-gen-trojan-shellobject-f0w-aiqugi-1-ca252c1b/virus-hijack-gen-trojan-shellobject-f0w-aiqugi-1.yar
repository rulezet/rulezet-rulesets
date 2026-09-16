rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dc8020e1d9e70efd3b10ea09db644b677bcbbea9fa195da895dd755b23ac968"

  strings:
    $s1 = "3o4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}