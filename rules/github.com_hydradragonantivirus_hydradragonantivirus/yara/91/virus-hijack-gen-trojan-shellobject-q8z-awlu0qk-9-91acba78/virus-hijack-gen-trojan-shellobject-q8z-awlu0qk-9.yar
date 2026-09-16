rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64525a8f058458b10c88baacf0a13c9eccfe4fbc7b17a85cab315f7b93f6787b"

  strings:
    $s1 = "tEAL`=n" fullword ascii
    $s2 = ":UmpH)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}