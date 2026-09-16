rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "597f4e56dd98d23cd37ea451c4db5060b7759b1b81157711ed98615576843eab"

  strings:
    $s1 = ">#4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}