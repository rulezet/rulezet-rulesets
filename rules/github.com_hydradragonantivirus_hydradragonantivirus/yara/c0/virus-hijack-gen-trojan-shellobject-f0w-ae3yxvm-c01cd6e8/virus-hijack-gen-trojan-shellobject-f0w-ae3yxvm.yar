rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ca85c4e2ed743cd7bdf0b64a8ddd1cc6592b8a2753b422d6d5e92f8f266cc87"

  strings:
    $s1 = ">4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}