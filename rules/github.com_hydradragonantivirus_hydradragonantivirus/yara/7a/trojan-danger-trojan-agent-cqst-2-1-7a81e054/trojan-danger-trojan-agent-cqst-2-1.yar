rule Trojan_Danger_Trojan_Agent_CQST_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.CQST_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afe60d8cbb5d67d0ed1cc6d6665a1e6c083425e1ac70800323f7a426304156ef"

  strings:
    $s1 = "rpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}