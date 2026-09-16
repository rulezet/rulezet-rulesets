rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_183 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_183.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b7e7eae0449c72632c3898d422be2b69e612aeb123baa5a88af68d895b44d97"

  strings:
    $s1 = "aRprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}