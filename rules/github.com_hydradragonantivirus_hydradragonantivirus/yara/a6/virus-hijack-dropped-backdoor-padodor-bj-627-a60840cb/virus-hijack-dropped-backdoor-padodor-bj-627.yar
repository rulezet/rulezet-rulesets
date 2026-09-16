rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_627 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_627.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61286c4a902141e4f076d22e79b64d1628f7681c9837e9ff9fbe1530cc9c23e7"

  strings:
    $s1 = "4-prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}