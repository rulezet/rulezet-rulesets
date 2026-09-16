rule sig_20151208_ef191654f97af7d9cc1d62986ae3590b {
  meta:
    description = "datamaliciousorder - file 20151208_ef191654f97af7d9cc1d62986ae3590b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1980574ee277b9aa511bc941c23b60678bff0d1b72cde4a7534d0cbfa4bc94ce"

  strings:
    $s1  = "return IXVlC;}function azeoIfyJonnkhbU(edloGcqZCLPOdlqDM){eval(edloGcqZCLPOdlqDM)}" fullword ascii
    $s2  = "var kuOvqIotCWCvS=[];for(mtokQez=(-803+803)/275;mtokQez<(33099+53)/259;mtokQez++){kuOvqIotCWCvS[mtokQez]=String.fromCharCode(mto" ascii
    $s3  = "function VVrTAjG(TXCLbhblLMnOEuCTYkqaclYLPgvXvZVQhRBj) {return !isNaN(parseFloat(TXCLbhblLMnOEuCTYkqaclYLPgvXvZVQhRBj)) && isFin" ascii
    $s4  = "push(\"108\");r.push(\"117\");r.push(\"100\");r.push(\"101\");r.push(\"115\");r.push(\"47\");r.push(\"112\");r.push(\"111\");r.p" ascii
    $s5  = "function VVrTAjG(TXCLbhblLMnOEuCTYkqaclYLPgvXvZVQhRBj) {return !isNaN(parseFloat(TXCLbhblLMnOEuCTYkqaclYLPgvXvZVQhRBj)) && isFin" ascii
    $s6  = "function zyZcXELxujuKieVzX(EXvku){gYEFdARBTqz= '';for(jobuCsvwCdC=(-327+327)/675; jobuCsvwCdC < (204+658)/431; jobuCsvwCdC++) {l" ascii
    $s7  = " return gYEFdARBTqz}" fullword ascii
    $s8  = "push(\"48\");r.push(\"52\");r.push(\"57\");r.push(\"57\");r.push(\"51\");r.push(\"117\");r.push(\"77\");r.push(\"51\");r.push(\"" ascii
    $s9  = "push(\"50\");Z.push(\"53\");Z.push(\"53\");Z.push(\"48\");Z.push(\"56\");Z.push(\"56\");Z.push(\"56\");Z.push(\"41\");Z.push(\"4" ascii
    $s10 = "push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"125\");Z.push(\"59\");Z.push(\"32\");Z.push(\"13\");Z.push(\"" ascii
    $s11 = "push(\"48\");Z.push(\"59\");Z.push(\"13\");Z.push(\"10\");Z.push(\"118\");Z.push(\"97\");Z.push(\"114\");Z.push(\"32\");Z.push(" ascii
    $s12 = "push(\"13\");Z.push(\"10\");Z.push(\"9\");Z.push(\"9\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"98" ascii
    $s13 = "function PIFxcwQeVev(QGMqJKVE,sBsCyu){return QGMqJKVE.split(sBsCyu)}" fullword ascii
    $s14 = "function kiiKhVjcEonxlHPdhweuHLjcwUWJIwRsmmltFUxKMLPCkkkyaQGSFI(LIFnclVuXVeUb,DeAOYKJmBSUWAu){ return kuOvqIotCWCvS[kwPkR(LIFncl" ascii
    $s15 = "push(\"13\");Z.push(\"10\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"115\");Z.push(\"77\");Z.push(\"" ascii
    $s16 = "kQez)}function kwPkR(bTKmbfwRNOJ,zEYqdddrPkPaV,WEXthAuZ){VRne=parseInt(bTKmbfwRNOJ,zEYqdddrPkPaV);IXVlC=VRne.toString(WEXthAuZ);" ascii
    $s17 = "push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"105\");Z.push(\"102\");Z.push(" ascii
    $s18 = "function zyZcXELxujuKieVzX(EXvku){gYEFdARBTqz= '';for(jobuCsvwCdC=(-327+327)/675; jobuCsvwCdC < (204+658)/431; jobuCsvwCdC++) {l" ascii
    $s19 = "TDebVrLy[jobuCsvwCdC]=(-410+410)/237; while(true) { if(lTDebVrLy[jobuCsvwCdC] > EXvku[jobuCsvwCdC].length-(243+312)/555) { break" ascii
    $s20 = "push(\"112\");Z.push(\"101\");Z.push(\"110\");Z.push(\"40\");Z.push(\"41\");Z.push(\"59\");Z.push(\"32\");Z.push(\"85\");Z.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}