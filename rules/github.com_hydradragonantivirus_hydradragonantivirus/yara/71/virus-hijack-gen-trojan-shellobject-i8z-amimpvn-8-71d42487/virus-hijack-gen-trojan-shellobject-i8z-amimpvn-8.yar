rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbc3c5fd73bdcb197d658b7cb91cdde49ab7a742b8a501bda9041ec6aac9b601"

  strings:
    $s1 = "/[policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}