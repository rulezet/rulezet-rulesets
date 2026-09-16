rule Virus_Hijack_Trojan_GenericKDZ_103285_858_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_858_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "526fe68fe5440236464621409d7dd0a8f32f7974e09c7b21070a13e22a01e8ca"

  strings:
    $s1 = "s=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}