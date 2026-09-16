rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa9fc2d237747a18edebb35d100426b30f0e21148c5be23b96712613b3fbb880"

  strings:
    $s1 = "*4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}