rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_574 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_574.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9d3703236b33edf25475ed84c91e29843d627d4bbc60f5212611fd0acb8f91f"

  strings:
    $s1 = "<prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}