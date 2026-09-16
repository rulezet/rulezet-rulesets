rule Virus_Hijack_Gen_Trojan_ShellObject_juZ_amBwvTb_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.juZ@amBwvTb_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dc792c5a0b2f0fb9f71259263660711d159e3861bcfdae926b9ffa370e253f3"

  strings:
    $s1 = "dWLM`YX\\k[fpRv~jkUkp[D^qR8HxC9VIEw~vTwfjkukp[leEs}lxBt~PTwd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}