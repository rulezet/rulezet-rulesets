rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5253ffc2e3cbbbfe34086ee6d655c4ddeb2f0ed650534d45ea03310c62bc27ff"

  strings:
    $s1 = "A4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}