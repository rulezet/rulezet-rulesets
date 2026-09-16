rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1ceb5388d81c9f913a8fa9becdb05b8f6585048fc9f85ea6833f96360efa3c3"

  strings:
    $s1 = "_]4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}