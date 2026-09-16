rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f566d14e1e5dc45ca604bd8f09e098ab37095cddabce05ac1baa62e4752333c"

  strings:
    $s1 = ".?AVsystem_error_category@?A0x05d1a880@system@boost@@" fullword ascii
    $s2 = ".?AVgeneric_error_category@?A0x05d1a880@system@boost@@" fullword ascii
    $s3 = "MBU Reserved 3" fullword wide
    $s4 = "Osfmui Installer Placeholder1" fullword wide
    $s5 = "@Traces triggered while servicing this thread's previous deferred traces were discarded." fullword wide
    $s6 = "Office Document Cache (ODC) Client test framework" fullword wide
    $s7 = "FIO Collab Scale Robots" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}