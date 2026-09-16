rule Virus_Hijack_Gen_Trojan_ShellObject_GyZ_am0pOwg_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GyZ@am0pOwg_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc1794157a030740a68658aae0a11e77bc1883fe2d8480885dea301ec4ce3427"

  strings:
    $s1 = "hEEl]I^g[`XmYA7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}