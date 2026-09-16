rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_370 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_370.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1087a27958328d1939b6389dea09607cfe01abb4975140a9328226feff9f8ba"

  strings:
    $s1 = "~prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}