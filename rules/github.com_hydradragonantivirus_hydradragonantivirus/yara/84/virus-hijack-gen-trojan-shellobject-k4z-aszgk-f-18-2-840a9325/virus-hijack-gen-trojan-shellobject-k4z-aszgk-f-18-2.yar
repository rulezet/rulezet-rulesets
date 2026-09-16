rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_18_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54d54f2aa2f5c28d98d219da497a49217b3526ddcbc00f449bc2ae5bafa50e82"

  strings:
    $s1 = "!pTvector<T> too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}