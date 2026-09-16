rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "492763c6c20bd4a0b441cb1023825fda1bafe104220eefe68dededabba6d5b3f"

  strings:
    $s1 = "8IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}