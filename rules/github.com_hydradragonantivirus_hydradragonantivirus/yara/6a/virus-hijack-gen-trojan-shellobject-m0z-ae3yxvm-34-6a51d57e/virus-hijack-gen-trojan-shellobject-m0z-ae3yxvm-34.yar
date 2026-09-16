rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_34 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_34.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1d9c02b28d27c71be360ab1667ed3532df4f43e9f8a8f1aacc244c44d959663"

  strings:
    $s1 = "9?4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}