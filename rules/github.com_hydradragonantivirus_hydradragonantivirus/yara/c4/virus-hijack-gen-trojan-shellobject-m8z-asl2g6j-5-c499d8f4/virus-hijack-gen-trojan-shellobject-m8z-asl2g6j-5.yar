rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aSl2g6j_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aSl2g6j_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5208ac0c5f65eaa18be7e136cbafdc258132db26851b177d2e54c2291e8e88e"

  strings:
    $s1 = "dupE`cl*" fullword ascii
    $s2 = "dupe`cl*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}