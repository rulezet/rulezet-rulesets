rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76e2c8c03430814a78e4f43b04494b54c898481a4360de4b56db347199fbf814"

  strings:
    $x1 = "PA<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
    $s2 = "blyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Adobe.Acrobat.Acrobat\" type=\"win32\"></assemblyIdentity><" ascii
    $s3 = "ndentAssembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><security><requestedPrivileges><requestedExecut" ascii
    $s4 = "ion>Adobe Acrobat 9.0</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii
    $s5 = "PA<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
    $s6 = "ngs></asmv3:application><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}