rule Virus_Hijack_Gen_Trojan_ShellObject_DuZ_amBwvTb_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DuZ@amBwvTb_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e42baf66b053d118e8e55a0a0f1b00a14e1ae2eb8e321f6ce86768b16099eeff"

  strings:
    $s1 = "7?ROBe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}