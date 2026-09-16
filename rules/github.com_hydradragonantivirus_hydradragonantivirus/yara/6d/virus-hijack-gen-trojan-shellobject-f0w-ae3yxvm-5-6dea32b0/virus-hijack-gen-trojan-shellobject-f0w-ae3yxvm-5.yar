rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54fdb53ef8956733ac32b9a89b09c7aefca3b082fe2ff229830da0d76717e5a0"

  strings:
    $s1 = "v`4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}