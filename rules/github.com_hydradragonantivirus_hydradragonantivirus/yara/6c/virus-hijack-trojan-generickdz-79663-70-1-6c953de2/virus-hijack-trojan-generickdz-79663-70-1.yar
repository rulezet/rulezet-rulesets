rule Virus_Hijack_Trojan_GenericKDZ_79663_70_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43e6d80cea4ce701d133316e89a38ac62ac6571f80fe0f53c1a8066c8504f871"

  strings:
    $s1 = "d?greW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}