rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_amBwvTb_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cc53141ac486f876718d320a98dd884ec7c97075883cb1aa6443ec7b8178368"

  strings:
    $s1 = "YcIe%:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}