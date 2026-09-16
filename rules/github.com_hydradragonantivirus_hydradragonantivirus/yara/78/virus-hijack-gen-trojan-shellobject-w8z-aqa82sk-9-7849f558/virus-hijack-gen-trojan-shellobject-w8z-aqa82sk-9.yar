rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac925f8649edd1a99943f0d56af56d87d7a208d17a08f44a5ad8e65d959f9bd1"

  strings:
    $s1 = "\\IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}