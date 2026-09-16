rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c11ec8d7408bac44d752a6aaf3c8e018681b58691624c97508be3554493ceb03"

  strings:
    $s1 = "g4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}