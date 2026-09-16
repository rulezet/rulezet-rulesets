rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_552 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_552.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dd59f6d46846762224d20cdda1bcdbfefabcedd89c119ce60dd2b7c670d40ab"

  strings:
    $s1 = "2are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}