rule Trojan_Danger_Trojan_Agent_EMNR_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.EMNR_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32f1306ac4a88bfd67270eda4fd97db178e0aa7cbcf1fb8e7f28b59e1a665f78"

  strings:
    $s1 = "6Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}