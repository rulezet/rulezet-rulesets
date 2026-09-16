rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_amBwvTb_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@amBwvTb_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d5b5481647c5377879c3834063ddaa58c822edc25c2d018789dfc4bca87bd1a"

  strings:
    $s1 = "!pTvector<T> too long" fullword ascii
    $s2 = "C@tRIO." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}