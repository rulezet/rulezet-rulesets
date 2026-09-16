rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4db80dae7e8c10687261aaddd81e38a15c846b6237db6d0ed510aeea2ba79c3"

  strings:
    $s1 = "Bassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}