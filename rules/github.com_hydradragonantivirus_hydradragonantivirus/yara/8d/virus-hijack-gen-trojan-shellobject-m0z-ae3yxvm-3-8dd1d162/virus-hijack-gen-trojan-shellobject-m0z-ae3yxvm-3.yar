rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b652683b78037ca82cc9a15c4406fa93145c43434cf87fe8189f4558c1c99d9b"

  strings:
    $s1 = "+4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}