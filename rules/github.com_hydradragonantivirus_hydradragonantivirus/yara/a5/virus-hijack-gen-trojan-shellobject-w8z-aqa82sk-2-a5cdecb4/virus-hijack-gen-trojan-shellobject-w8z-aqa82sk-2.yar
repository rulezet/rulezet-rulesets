rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b5f4a25ff1fc66db2df74592ab5266ee356ad38bd547fb918b7f1f6f7d51a48"

  strings:
    $s1 = "4-IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}