rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d776e2769a0cf8a6686010d5d45c9a40313fa3d9a78ab4bfe9ed3a0ad93feb9"

  strings:
    $s1 = "`4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}