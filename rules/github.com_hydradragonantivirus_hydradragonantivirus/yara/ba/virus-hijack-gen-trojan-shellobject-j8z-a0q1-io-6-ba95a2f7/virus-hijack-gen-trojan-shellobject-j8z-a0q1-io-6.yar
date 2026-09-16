rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_a0q1_io_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0q1@io_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adde7b13a5cf6f03aabca6bae2476deaf8168fe2e4fc231914bfa7076f147860"

  strings:
    $s1 = "{Xor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}