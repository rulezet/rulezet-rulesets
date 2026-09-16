rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79533664dc21612d0d53e99144474245c9eed47bddf27850b2e69749f3166855"

  strings:
    $s1 = "TTTTTTTTT begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}