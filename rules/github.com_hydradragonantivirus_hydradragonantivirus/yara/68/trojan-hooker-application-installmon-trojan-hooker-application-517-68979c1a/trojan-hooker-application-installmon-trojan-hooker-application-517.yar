rule _Trojan_Hooker_Application_InstallMon_Trojan_Hooker_Application__517 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Application.InstallMon.vir, Trojan.Hooker_Application.InstallMon_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "585b97e070392f27740a01ab54cdc31c4190aa2b63fe77668af34104016da1f7"
    hash2       = "5db47f309805f27fa0d5b4ee07087a023e4e620955baabb5e3863671aecd3c3d"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "</application></compatibility><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExe" ascii
    $s3 = "</application></compatibility><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExe" ascii
    $s4 = "xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsof" ascii
    $s5 = "</dependentAssembly></dependency><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and all of them)
    ) or (all of them)
}