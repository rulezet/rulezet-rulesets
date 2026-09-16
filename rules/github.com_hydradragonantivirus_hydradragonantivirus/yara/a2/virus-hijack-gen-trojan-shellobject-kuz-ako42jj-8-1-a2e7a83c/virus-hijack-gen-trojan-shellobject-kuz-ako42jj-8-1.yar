rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2d8f64d585c4504658a80ef5d76d9cd42206c579d26a3e007bb74cc44b28ce9"

  strings:
    $x1 = "c:\\users\\jaber\\documents\\visual studio 2012\\Projects\\skee\\skee\\obj\\Debug\\skee.pdb" fullword ascii
    $s2 = "(At runtime, the labels' text will be replaced with the application's assembly information." fullword ascii
    $s3 = "Customize the application's assembly information in the Application pane of Project Designer.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}