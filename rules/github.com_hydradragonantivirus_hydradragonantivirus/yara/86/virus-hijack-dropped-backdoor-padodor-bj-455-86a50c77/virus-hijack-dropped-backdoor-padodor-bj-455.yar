rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_455 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_455.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a565d0d3c4fddb73ddb1629f6fca9e85f18fe37adbf9f4312909024a19599d2"

  strings:
    $s1 = "2are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}