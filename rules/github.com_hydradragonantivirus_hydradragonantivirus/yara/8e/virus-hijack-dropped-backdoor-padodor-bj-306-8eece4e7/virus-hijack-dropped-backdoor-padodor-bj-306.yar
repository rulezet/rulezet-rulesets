rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_306 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_306.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a29b49eefd8311a807d382181d894e9d50a993f3cda097aa2ba54e6ea5fcd272"

  strings:
    $s1 = "Tare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}