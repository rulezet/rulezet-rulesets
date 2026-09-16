rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_auCCoZb_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0433b97b013b517aa3c1218a45f45b495d062bea6284daf1688ab00c8a16773"

  strings:
    $s1 = "whole dev %s, devno 0x%04X" fullword ascii
    $s2 = "partition dev %s, devno 0x%04X" fullword ascii
    $s3 = "access: '%s'" fullword ascii
    $s4 = "read partition name %s" fullword ascii
    $s5 = "freeing %s" fullword ascii
    $s6 = "visuaL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}