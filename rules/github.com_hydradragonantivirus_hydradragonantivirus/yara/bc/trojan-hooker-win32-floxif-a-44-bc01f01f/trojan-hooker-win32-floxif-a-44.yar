rule Trojan_Hooker_Win32_Floxif_A_44 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_44.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f78705ce924df5869188fb6884885ed8bb7ac6c07393446873fd9ee431560fe"

  strings:
    $s1  = "WARNING: SetLegacyAclDefaults- Invalid security descriptor type." fullword ascii
    $s2  = "WARNING: SetAclDefaults- Invalid security descriptor type." fullword ascii
    $s3  = "ASUS Com Service" fullword ascii
    $s4  = "TasComSvc(TComponent* Owner)" fullword ascii
    $s5  = "@@Atkexcomsvc_tlb@Initialize" fullword ascii
    $s6  = "@@Atkexcomsvc_atl@Finalize" fullword ascii
    $s7  = "Invalid message map ID (%i)" fullword ascii
    $s8  = "LoadNeededLibrary complete" fullword ascii
    $s9  = "@@Atkexcomsvc_tlb@Finalize" fullword ascii
    $s10 = "Offer Remote Assistance Helpers" fullword ascii
    $s11 = "@@Atkexcomsvc_atl@Initialize" fullword ascii
    $s12 = "CatReg->RegisterClassImplCategories(TStringConverter<char>::AnsiToGUID(pClassID), 1, &tempGUID)" fullword ascii
    $s13 = "TInternalRegistrationHelpers::CreateRegKey(_T(\"Component Categories\\\\{13E85B3C-9508-11D2-AB63-00C04FA35CFA}\"), _T(\"409\"), " ascii
    $s14 = "TInternalRegistrationHelpers::CreateRegKey(_T(\"Component Categories\\\\{13E85B3C-9508-11D2-AB63-00C04FA35CFA}\"), _T(\"409\"), " ascii
    $s15 = "Get rom size: " fullword ascii
    $s16 = "Invalid pixel format!Cannot change the size of an icon Invalid operation on TOleGraphic" fullword wide
    $s17 = "std::_Tree_val<std::_Tmap_traits<unsigned char,std::map<unsigned short,std::pair<unsigned long,BiosItemCollector *>,std::less<un" ascii
    $s18 = "<Using Default Permissions>" fullword ascii
    $s19 = "std::map<unsigned char,std::map<unsigned short,std::pair<unsigned long,BiosItemCollector *>,std::less<unsigned short>,std::alloc" ascii
    $s20 = "long,BiosItemCollector *> >,0> > *" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}