rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dad597d921ceaeb4cbea392737a8509a5216b753bc1d5e90a3e1620b148b467a"

  strings:
    $s1 = "*Niter" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}