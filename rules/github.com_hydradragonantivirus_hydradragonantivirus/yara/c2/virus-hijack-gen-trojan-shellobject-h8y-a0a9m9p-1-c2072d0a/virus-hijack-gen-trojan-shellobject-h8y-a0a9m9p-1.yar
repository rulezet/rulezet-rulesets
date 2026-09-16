rule Virus_Hijack_Gen_Trojan_ShellObject_h8Y_a0a9m9p_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8Y@a0a9m9p_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9067d78df050263d6ec3832b11d8dbb499b3ebbb96a3e85dae5ad220465451e8"

  strings:
    $s1 = "lSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}