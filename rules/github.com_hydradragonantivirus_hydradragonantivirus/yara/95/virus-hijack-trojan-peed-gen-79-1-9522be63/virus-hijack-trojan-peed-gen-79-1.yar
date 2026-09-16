rule Virus_Hijack_Trojan_Peed_Gen_79_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabe5dba8eb9eb55c17ca40928d872bd794dc0d982414772340bf38239bd7464"

  strings:
    $s1 = "Q)aMMA" fullword ascii
    $s2 = "_(NAiS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}