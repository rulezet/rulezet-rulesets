rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98475357e149d60810b07d077b080772a99772796d8549ab9867d59cb6d55832"

  strings:
    $s1 = "]are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}