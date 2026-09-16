rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_561 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_561.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4d47159a1ce1f182c0c62920d1712de374de20f379479a0d9fcc818d009850b"

  strings:
    $s1 = "pQare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}