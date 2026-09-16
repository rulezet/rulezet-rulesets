rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_199 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_199.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "894d8837fba2eab59105b16ff94431b79915162db719d1f1eca42b97f57e14ca"

  strings:
    $s1 = ",are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}