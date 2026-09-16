rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6198700a263c731aad51cd269532123f6acd1aa4a6dc47759d39dc3e57a5768f"

  strings:
    $s1 = "Juassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}