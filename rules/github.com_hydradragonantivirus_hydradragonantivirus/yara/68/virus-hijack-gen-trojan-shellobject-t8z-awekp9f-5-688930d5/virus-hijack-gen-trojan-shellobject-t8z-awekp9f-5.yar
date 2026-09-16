rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49b17b014a25aa3729fc4fb7d71b95f0283c833132a0a9d40f4def40dd62fe53"

  strings:
    $s1 = "2kIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}