rule Virus_Hijack_Gen_Trojan_ShellObject_EuZ_aiy413e_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7efb2daca2c6fc0b5ba27653a4ed96efea2fd46bd8490f0e0cacf98f1d58f6aa"

  strings:
    $s1 = "process id %u" fullword ascii
    $s2 = "memory address : %x" fullword ascii
    $s3 = "d File Info>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}