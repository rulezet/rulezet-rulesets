import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_8_2_Virus_Hijac_102 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d20ab643ced0f5d46398d91d8d0cd4e7d4b36c426e1bb81ec60db083fcd0031"
    hash2       = "27d90fddaaa83a203f9ca03e2dbd9be67a761941ead92bff81de692b7ef776ba"

  strings:
    $s1  = "Method InvokeMultipleItemCommand - Invokes a command for the passed-in item paths. The ItemSelectionType parameter describes wha" ascii
    $s2  = "ILoginCallback is called when asynchronous operation Login on ISyncEngine completes.WWi" fullword ascii
    $s3  = "IGetItemPropertiesCallback is invoked when retrieval of item properties is complete.WWc" fullword ascii
    $s4  = "ISetItemPropertiesCallback is called to get the results of attempt to write collaborative metadata.WWW" fullword ascii
    $s5  = "IGetPauseStateCallback is called when asynchronous operation BeginGetPauseState on ISyncEngine completes.Wk" fullword ascii
    $s6  = "IGetSyncStatusCallback is called when the asynchronous operation BeginGetSyncStatus on ISyncEngine completes.Wd" fullword ascii
    $s7  = "Method to open the settings dialog.WWW" fullword ascii
    $s8  = "IDeleteLibraryCallback is called when asynchronous operation DeleteLibrary on ISyncEngine completes.WWk" fullword ascii
    $s9  = "Method to open the selective sync dialog.W#" fullword ascii
    $s10 = "IMapLibraryCallback is called when asynchronous operation MapLibrary on ISyncEngine completes.b" fullword ascii
    $s11 = "ICreateLibraryCallback is called when asynchronous operation CreateLibrary on ISyncEngine completes.WW^" fullword ascii
    $s12 = "IUnmapLibraryCallback is called when asynchronous operation UnmapLibrary on ISyncEngine completes.d" fullword ascii
    $s13 = "IGetAllSharedFoldersCallback is called to return a list of the known owned and edited shared foldersWWT" fullword ascii
    $s14 = "t kind of items are containedW)" fullword ascii
    $s15 = "type<(" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b941ddedcc51e5706d41335adb4e6b2a" and (8 of them)
    ) or (all of them)
}