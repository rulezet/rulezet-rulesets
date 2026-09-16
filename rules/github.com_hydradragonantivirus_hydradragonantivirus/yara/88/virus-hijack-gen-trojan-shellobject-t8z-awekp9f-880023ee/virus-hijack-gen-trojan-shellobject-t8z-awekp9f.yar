rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18cc68539d08b524710fcff1d9790fa66ed7e6c5c6d5bf0dc81bc5404a03eed3"

  strings:
    $s1 = "NIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}