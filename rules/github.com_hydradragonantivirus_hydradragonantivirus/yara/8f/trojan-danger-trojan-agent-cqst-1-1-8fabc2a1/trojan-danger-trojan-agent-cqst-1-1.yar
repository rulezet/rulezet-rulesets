rule Trojan_Danger_Trojan_Agent_CQST_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.CQST_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2ab2cb6597c14852ef845f98d41b9aa34212830e9ee6f62a886179f63e4bcd"

  strings:
    $s1 = "2purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}