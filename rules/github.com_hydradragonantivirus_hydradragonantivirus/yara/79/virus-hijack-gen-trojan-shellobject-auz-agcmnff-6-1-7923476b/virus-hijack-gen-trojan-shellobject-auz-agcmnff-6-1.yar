rule Virus_Hijack_Gen_Trojan_ShellObject_AuZ_aGCmnff_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.AuZ@aGCmnff_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3337957377c9fe268c34210a63a2501062250c217608474e434b9d8c65c805"

  strings:
    $s1 = "bj : error LNK2001: unresolved external symbol __imp__InitCommonControls@0error LNK2001: unresolved external symbol __imp__Inter" ascii
    $s2 = "failed with error %d: %s" fullword ascii
    $s3 = "Mozilla/5.0 (IE6 ; compatible)" fullword ascii
    $s4 = "bj : error LNK2001: unresolved external symbol __imp__InitCommonControls@0error LNK2001: unresolved external symbol __imp__Inter" ascii
    $s5 = "Com Infrastructure" fullword ascii
    $s6 = "DVT Soft Ltd." fullword wide
    $s7 = "Copyright @ DVT 2006" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}