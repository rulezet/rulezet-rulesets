rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72ff38e0fd6bae2b9918defca54f2f5deb1a1e7b2ace54c3473aaa7e13ecf669"

  strings:
    $s1 = "`s4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}