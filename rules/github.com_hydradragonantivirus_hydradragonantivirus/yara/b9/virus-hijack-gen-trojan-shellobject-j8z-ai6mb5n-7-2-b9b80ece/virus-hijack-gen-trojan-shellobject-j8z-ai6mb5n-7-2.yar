rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ai6MB5n_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ai6MB5n_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9c7fbe792fff01a896d5d176e5a79cced063bbc77cd138f08f261dfa0cff7d1"

  strings:
    $s1 = "U[TcHe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}