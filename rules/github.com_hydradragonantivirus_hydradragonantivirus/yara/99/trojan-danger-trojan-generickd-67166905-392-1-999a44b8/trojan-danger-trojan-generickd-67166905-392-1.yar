rule Trojan_Danger_Trojan_GenericKD_67166905_392_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_392_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fccebc2d178aa6970d603ec46fccccfc5a4cb37216cf65356ee495bc8e035ba"

  strings:
    $s1 = "access to the Oracle iSupport program may not be licensed as Employee Users, but must be licensed as `" fullword ascii
    $s2 = ":dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}