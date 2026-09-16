rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_407 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_407.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb34d439fdb9604f76b104844003ee27a24166f862ef3aa19fe1ca8f0d9ec28f"

  strings:
    $s1 = "y:are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}