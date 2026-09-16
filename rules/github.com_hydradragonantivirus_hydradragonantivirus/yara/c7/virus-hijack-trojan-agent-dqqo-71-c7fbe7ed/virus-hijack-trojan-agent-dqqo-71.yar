rule Virus_Hijack_Trojan_Agent_DQQO_71 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_71.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97626316d4d182e9b62e0ddf56445c2536ce7bc8eba8d9ea42eda98f5383d06d"

  strings:
    $s1 = "NIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}