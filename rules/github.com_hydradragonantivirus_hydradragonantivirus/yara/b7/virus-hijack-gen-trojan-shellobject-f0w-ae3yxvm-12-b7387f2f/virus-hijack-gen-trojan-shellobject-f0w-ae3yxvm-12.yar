rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a6b01c5c87a445c3685884a8002b79ce468d0c7f7e95521e6ef50e4fc0398ce"

  strings:
    $s1 = "8~4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}