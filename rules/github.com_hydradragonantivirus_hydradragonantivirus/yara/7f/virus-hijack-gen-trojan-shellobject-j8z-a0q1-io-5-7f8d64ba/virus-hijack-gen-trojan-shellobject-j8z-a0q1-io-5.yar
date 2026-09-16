rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_a0q1_io_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0q1@io_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "417a9883f29c35e31f2dee0c4bbc66bc20f51094223c8605e2993097a9111ae1"

  strings:
    $s1 = "^or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}