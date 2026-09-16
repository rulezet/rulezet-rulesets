rule Trojan_Autorun_Trojan_GenericKD_72517131_166_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_166_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da796e590d4e957546a32199fbc0e519542177c823f7e2c9a98e2c1ba280fbee"

  strings:
    $s1 = "_debug': False, " fullword ascii
    $s2 = "e, 'x_seq': None, 'f_seq': None,0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}