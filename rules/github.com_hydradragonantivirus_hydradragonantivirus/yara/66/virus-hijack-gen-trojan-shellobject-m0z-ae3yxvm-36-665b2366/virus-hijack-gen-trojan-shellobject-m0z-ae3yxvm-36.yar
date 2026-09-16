rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_36 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_36.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6f2a3c2fda37635864fa3ceebd972cdf31f072e67633a68b05369588612bd60"

  strings:
    $s1 = "l4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}