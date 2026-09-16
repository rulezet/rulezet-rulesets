rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oUJio_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f3551ecb51ee1e5cfd32e46b66c1fd2d8b5ab9855f5a87fbb19d7d3efd08577"

  strings:
    $s1 = "!ze< CRAN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}