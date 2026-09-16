rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbbb1509b37f4da7f8864a7d665432c00cce4a13e63afcaa0840e2e2f493a224"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><noInherit></noInherit><assemblyIdentity processorA" ascii
    $s2 = "  -O, --show-options, --usage  go to command-line options node" fullword ascii
    $s3 = "><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" processorAr" ascii
    $s4 = "  info --show-options emacs    start at node with emacs' command line options" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}