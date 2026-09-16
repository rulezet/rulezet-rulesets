rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_685_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_685_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "782e05320ce3ef0b97ecb79a96f35c9f6a9dd5bbabf255a828bf2a6781d71925"

  strings:
    $s1 = "Infect" fullword ascii
    $s2 = "explorer " fullword wide
    $s3 = "Rich{yi" fullword ascii
    $s4 = "Worm Kalem" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}