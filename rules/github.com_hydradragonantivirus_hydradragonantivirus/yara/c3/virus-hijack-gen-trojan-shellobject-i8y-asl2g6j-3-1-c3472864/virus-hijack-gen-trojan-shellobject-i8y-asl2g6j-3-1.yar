rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b91fc51f8a846e5cf1a2e47a0c1406eadb13531d0dd694321c35f205081acc31"

  strings:
    $s1 = "Giz kodota tiziwibumap<Pegis lul jefimiwifeyopud remosacuhuyige cimeganoregiwu cuya" fullword wide
    $s2 = "pICO{S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}