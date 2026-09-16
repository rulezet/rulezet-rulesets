rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_198 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_198.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6bd1f6c975b5cf3bda27f861e9fa28905b0952017e653f12e7ef68365022392"

  strings:
    $s1 = "8Pprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}