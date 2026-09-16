rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_amBwvTb_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efb13ca5a6fc48fcb95661ebfcfab8264ddab2b112d00789090e2a79c86ff436"

  strings:
    $s1 = "DILo&!\"b,,(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}