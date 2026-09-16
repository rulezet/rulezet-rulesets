rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71ef35b2167dbaea9589e0b0460f0c6c6b4c7a69ce02a918cb723859d46143c2"

  strings:
    $s1 = "UWassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}