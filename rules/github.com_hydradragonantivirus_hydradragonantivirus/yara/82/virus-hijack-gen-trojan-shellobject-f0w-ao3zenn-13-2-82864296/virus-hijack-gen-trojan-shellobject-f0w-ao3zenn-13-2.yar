rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d9b865aa4bb100418ef0828bc8e1eb1186f1cd0a8232888a2b733b6f06c396"

  strings:
    $s1 = "\"^}WaIk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}