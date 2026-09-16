rule Virus_Hijack_Trojan_Agent_DQQO_400 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_400.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5439733dd19590c46410e589c868be22f4885cf97fcf8d1c11b1dbad898a36b"

  strings:
    $s1 = "\\]IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}