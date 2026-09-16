rule Virus_Hijack_Trojan_GenericKDZ_79663_58_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_58_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b910575cc7f3d91c01813816c5ceaeb45596f55168d7e6ec63ce1f920cf026d9"

  strings:
    $s1 = "U)siZz" fullword ascii
    $s2 = "#cURB'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}