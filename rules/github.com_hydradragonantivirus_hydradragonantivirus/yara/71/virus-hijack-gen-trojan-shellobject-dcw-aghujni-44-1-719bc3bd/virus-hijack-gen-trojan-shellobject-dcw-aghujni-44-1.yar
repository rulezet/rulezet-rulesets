rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_44_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23b68b8810b709269e2d8aa4a65a45d404d029692e8e9ae63880e9e121e084df"

  strings:
    $s1 = "fc8fi<kink@nqDsqvsHvyL{y~{P~" fullword ascii
    $s2 = "b`bice" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}