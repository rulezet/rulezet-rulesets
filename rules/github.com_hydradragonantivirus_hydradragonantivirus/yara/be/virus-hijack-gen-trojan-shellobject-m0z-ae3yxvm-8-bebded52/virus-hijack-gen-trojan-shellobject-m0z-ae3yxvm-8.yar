rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91d8e8794abea0cc774190306a4090bfc7acb315d58f84ecb7c9538a9306ff62"

  strings:
    $s1 = "g4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}