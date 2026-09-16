rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_25 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcc35e5c4e1076fd50b41b969fb08b863a92730377169e980a3105645356d882"

  strings:
    $s1 = "$4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}