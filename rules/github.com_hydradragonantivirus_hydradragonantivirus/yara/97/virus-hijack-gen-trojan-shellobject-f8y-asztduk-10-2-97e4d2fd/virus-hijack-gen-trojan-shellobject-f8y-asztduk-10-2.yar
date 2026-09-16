rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcaab7d20b29355a1d50b575784c54b261bd708fa1465e0d6dd2b6fb8caa51c7"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s2 = "Adobe .com/AcrobatUpd812" fullword ascii
    $s3 = "Microsoft Script Editor" fullword wide
    $s4 = ".Microsoft Script Edito" fullword wide
    $s5 = "Google Update Core" fullword wide
    $s6 = "re=\"X86\" name=\"mse7\" type=\"win32\"></assemblyIdentity><description>mse7</description><dependency><dependentAssembly><assemb" ascii
    $s7 = "Cannot load the Microsoft Solution Designer International DLL" fullword wide
    $s8 = "An error has occurred. Microsoft Solution Designer cannot start." fullword wide
    $s9 = "Cannot initialize pluggable UI" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}