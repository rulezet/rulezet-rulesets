rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_440 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_440.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9570f372356926531ff5b698dae8d99b5dde617b431be3ef5272340863ad1319"

  strings:
    $s1 = "dzIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}