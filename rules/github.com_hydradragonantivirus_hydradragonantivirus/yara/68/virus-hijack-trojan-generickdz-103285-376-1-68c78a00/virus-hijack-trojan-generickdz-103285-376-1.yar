rule Virus_Hijack_Trojan_GenericKDZ_103285_376_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_376_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c74fec7bb54661d585994669cf69d9da0f7d4848174e11c3fc297df6349d3a77"

  strings:
    $s1 = "s=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}