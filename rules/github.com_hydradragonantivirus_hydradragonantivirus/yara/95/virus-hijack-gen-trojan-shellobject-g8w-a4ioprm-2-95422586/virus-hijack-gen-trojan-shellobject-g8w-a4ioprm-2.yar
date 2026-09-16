rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IOpRm_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IOpRm_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b31419cb0a0ac9fe225e9db22c5a0d215886e1f094f9a636022a992bff4d9d5b"

  strings:
    $s1 = "L:tUTe" fullword ascii
    $s2 = "dRIB'_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}