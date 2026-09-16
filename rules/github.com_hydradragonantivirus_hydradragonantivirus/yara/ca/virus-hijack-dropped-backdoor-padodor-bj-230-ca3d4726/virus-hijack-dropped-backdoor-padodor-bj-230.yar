rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_230 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_230.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e39febd6647c9284d6f77d39a12742e10c2ea5cb1d7392b8c239a850f0c8737"

  strings:
    $s1 = "vsare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}