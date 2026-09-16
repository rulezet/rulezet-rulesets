rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_7_2_Virus_Hijac_86 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96703675d1d85d71d9471c2f407b3dce01ee6eaece009751c37f3e89bf96c723"
    hash2       = "874c2e6f552ddd05c4a2f51a7859422bdb36992ab31f92480f15a355eaf799f8"

  strings:
    $s1  = " na www.adobe.com.  Adobe v" fullword ascii
    $s2  = " program pre [BrandName]SetupCompleteErrorBack< &Sp" fullword ascii
    $s3  = "cie Reader AIRReaderBrowserIntegrationIntegr" fullword ascii
    $s4  = "cii Adobe Acrobat Reader DCOwnership_ChkBoxNastavi" fullword ascii
    $s5  = "cie Adobe Reader.Sada s" fullword ascii
    $s6  = "cie Adobe ReaderT" fullword ascii
    $s7  = "ciu Adobe PDF ReaderAppsInUseSilentAbortJe spusten" fullword ascii
    $s8  = "cie Reader PDFSearchAndIndexSearch a IndexTento komponent obsahuje z" fullword ascii
    $s9  = "cia Adobe Reader nastaven" fullword ascii
    $s10 = "bore ReadMe v prie" fullword ascii
    $s11 = "inkoch.Cesta [2] alebo disk je neplatn" fullword ascii
    $s12 = " program sa teraz ukon" fullword ascii
    $s13 = " disk je v" fullword ascii
    $s14 = " program kliknut" fullword ascii
    $s15 = "ovanie star" fullword ascii
    $s16 = "ciu Adobe Reader alebo Adobe AcrobatERROR_CANNOT_OPTIMIZE_DISKPOZN" fullword ascii
    $s17 = " program vytvor" fullword ascii
    $s18 = "enie publikovania inform" fullword ascii
    $s19 = "asti sa nain" fullword ascii
    $s20 = "stupcov a polo" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}