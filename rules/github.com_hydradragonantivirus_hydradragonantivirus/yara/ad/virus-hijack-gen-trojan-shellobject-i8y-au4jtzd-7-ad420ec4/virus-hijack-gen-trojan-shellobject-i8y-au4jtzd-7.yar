rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au4JtZd_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au4JtZd_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbf34b0cac3730da35c0a76ec789d3fa0a6020b14c843287db3e357789a29c82"

  strings:
    $x1  = "ExcelClrLoader - Could not get proc address for CorBindToRuntimeEx.?" fullword wide
    $x2  = "ExcelClrLoader - Could not load library mscoree.dll." fullword wide
    $s3  = "ExcelClrLoader - Could not get proc address for GetCORVersion.8" fullword wide
    $s4  = "ExcelClrLoader - Could not get proc address for CLRCreateInstance." fullword wide
    $s5  = "If no version is specified in the <addin>.dna file, the host will attempt to load .NET version 2.0." fullword wide
    $s6  = "ExcelClrLoad - Host->Start failed." fullword wide
    $s7  = "Review the other managed Excel add-ins that are loaded, or ensure that the .NET 2.0 runtime loads by setting an appropriate 'sup" wide
    $s8  = "Review the other add-ins that are loaded, or ensure that the .Net 2.0 runtime loads by setting an approriate 'supportedRuntime' " wide
    $s9  = "A problem occurred while attempting to load the requested version of the Microsoft .NET runtime:" fullword wide
    $s10 = "MetaHost could not load the requested version of the .NET runtime." fullword wide
    $s11 = "A problem occurred while attempting to load the .NET runtime:s" fullword wide
    $s12 = "This is possible if a configuration file or another managed add-in forces an older version of the runtime to load (only one vers" wide
    $s13 = "A problem occurred while attempting to load the .NET runtime:[" fullword wide
    $s14 = "This error can occur if the .NET runtime is not installed, if version 2.0 or later is not installed, if the AppPatch registry en" wide
    $s15 = "This is an unexpected error. Please report this error to the add-in developer.ZThe .NET runtime was loaded but could not be star" wide
    $s16 = "A problem occurred while an add-in was being initialized (InitializeIntegration failed - {1})." fullword wide
    $s17 = "Registration failed for function or command: '{0}'" fullword wide
    $s18 = "This Excel add-in requires an '<addin>.dna' configuration file which matches the '<addin>.xll' file (or an embedded resource wit" wide
    $s19 = "Check that there is no obsolete version of ExcelDna.Integration.dll present. This file can be safely deleted." fullword wide
    $s20 = "$AppDomainSetup could not be created.!ApplicationBase could not be set.AppDomain could not be created.MThe ASSEMBLY 'EXCELDNA.L" wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}