rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7aaedf86150571110cbb1271ff576304ed6b6b5c0d49a32a3f5d12b922e3454b"

  strings:
    $s1 = "oM4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}