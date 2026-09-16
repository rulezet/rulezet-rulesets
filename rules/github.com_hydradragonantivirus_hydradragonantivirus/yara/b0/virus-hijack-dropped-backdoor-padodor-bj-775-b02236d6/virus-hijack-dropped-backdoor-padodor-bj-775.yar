rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_775 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_775.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47f1b238d65f3e886efdaaf12e17b78a3fa2b7ab007ead44ddce35a607bc4cee"

  strings:
    $s1 = "Qare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}