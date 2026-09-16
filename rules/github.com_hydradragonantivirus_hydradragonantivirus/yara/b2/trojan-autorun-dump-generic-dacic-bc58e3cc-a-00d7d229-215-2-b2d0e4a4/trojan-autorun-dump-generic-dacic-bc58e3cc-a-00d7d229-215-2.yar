rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_215_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_215_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "048af4b7abfd564607619118136ddb8dd1be8ce930889bedefe9c5fe803a479c"

  strings:
    $x1 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\"><assemblyIdentity version=\"1.0.0.0\" name=\"MyAppl" ascii
    $x2 = "function Local:Get-Delegate{Param([OutputType([Type])][Parameter(Position=0)][Type[]]$ParameterTypes,[Parameter(Position=1)][Typ" wide
    $s3 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\"><assemblyIdentity version=\"1.0.0.0\" name=\"MyAppl" ascii
    $s4 = "y></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><security><requestedPrivileges xmlns=\"urn:schemas-microsof" ascii
    $s5 = ".app\"></assemblyIdentity><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Contro" ascii
    $s6 = "[Reflection.Assembly]::Load([Microsoft.Win32.Registry]::LocalMachine.OpenSubkey('SOFTWARE').GetValue('nslookstager')).EntryPoint" wide
    $s7 = "s></security></trustInfo><ms_compatibility:compatibility xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" x" ascii
    $s8 = "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"></ms_compatibility:supportedOS></ms_compatibility:application></ms_compatibility:compati" ascii
    $s9 = "ns=\"urn:schemas-microsoft-com:compatibility.v1\"><ms_compatibility:application xmlns:ms_compatibility=\"urn:schemas-microsoft-c" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}