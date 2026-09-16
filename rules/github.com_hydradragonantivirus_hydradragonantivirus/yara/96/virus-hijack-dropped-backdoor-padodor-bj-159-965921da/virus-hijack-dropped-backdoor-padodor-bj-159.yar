rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_159 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_159.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbb43de8eeef46d82e9c0a5ae13df32e2e0bc90ff8855d22dca040e1f9b75cd"

  strings:
    $s1 = "mTand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}