rule Virus_Hijack_Trojan_Agent_DQQO_398 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_398.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354ce3aa4c4629f17ab7c2b1a2bbcc51966cd41e662a92567a1449511d1fc30c"

  strings:
    $s1 = "aIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}