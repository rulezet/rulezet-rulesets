rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_592 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_592.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "434b72a742d49d55224b4d03530e96bb0c8a1de3b42669419d6b1a71d09065af"

  strings:
    $s1 = "&Dare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}