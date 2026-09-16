rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05270b3f20d4434e7a9dc716c57346d9faf93d3eeadc0cc893dd0603c3e694a2"

  strings:
    $s1 = "q|T5i&oPAl" fullword ascii
    $s2 = ":TOle." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}