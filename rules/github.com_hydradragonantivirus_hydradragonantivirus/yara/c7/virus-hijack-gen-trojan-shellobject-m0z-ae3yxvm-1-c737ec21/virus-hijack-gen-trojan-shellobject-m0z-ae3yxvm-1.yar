rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baeeb6bcf9a6c66cdc69e692faf80e589db3f6439b20160ef78e431bf86928e6"

  strings:
    $s1 = "'4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}