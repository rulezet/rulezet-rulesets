rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226a7f8597330d08713c3e4fc9bd242f1603f3063e35743e0cf5310125b6f1a3"

  strings:
    $s1 = "nOiNT(@^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}