rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ee254ce29becab5ab3d91832c610b6fb9f9baca22b2c8c592cfe508f35b9e15"

  strings:
    $s1 = "Management Support Team1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}