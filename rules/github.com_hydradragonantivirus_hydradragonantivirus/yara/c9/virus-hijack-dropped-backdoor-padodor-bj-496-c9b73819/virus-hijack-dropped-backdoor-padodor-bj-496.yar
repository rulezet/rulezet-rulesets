rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_496 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_496.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85233e68ab7cc37a2b4183e578a6519eebdb4d60f089e3e8cb5135bf53fc7616"

  strings:
    $s1 = "Qe ogrE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}