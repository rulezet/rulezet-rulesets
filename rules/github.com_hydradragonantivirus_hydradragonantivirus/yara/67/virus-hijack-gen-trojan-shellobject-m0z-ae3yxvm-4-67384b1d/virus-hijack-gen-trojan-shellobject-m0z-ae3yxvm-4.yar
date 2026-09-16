rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f97f2b4c87971f98821883c4928fd865db15122743d4c34d8785583fd6404565"

  strings:
    $s1 = "T4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}