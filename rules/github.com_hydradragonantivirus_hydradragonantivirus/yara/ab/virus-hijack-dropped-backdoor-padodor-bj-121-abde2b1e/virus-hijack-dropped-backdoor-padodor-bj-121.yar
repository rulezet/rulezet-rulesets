rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_121 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_121.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f4de21b01bbf414d07663ca6401621c140731a4ad3fa82463da91979a4966d5"

  strings:
    $s1 = "KLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}