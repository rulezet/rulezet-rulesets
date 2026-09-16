rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eba8c91efb7044ec69e8cd635e857a7c1bca35045ee8a81a5ae06cdc437d89fc"

  strings:
    $s1 = "<IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}