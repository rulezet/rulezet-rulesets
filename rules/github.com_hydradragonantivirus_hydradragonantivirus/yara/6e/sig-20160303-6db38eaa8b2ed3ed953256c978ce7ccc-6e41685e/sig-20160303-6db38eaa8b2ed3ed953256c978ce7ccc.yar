rule sig_20160303_6db38eaa8b2ed3ed953256c978ce7ccc {
  meta:
    description = "datamaliciousorder - file 20160303_6db38eaa8b2ed3ed953256c978ce7ccc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64b08dd3f883f5cb03562200028893067879fcbcdbd9fe09c6fc121d644f31c6"

  strings:
    $s1  = "var PXWKH = \"qthdKL aqF pt.Shell qsABGDD Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var dQR = (vdg + \"TTP\" + \" MsDcLMl HGQHb XML ream St DLKxHbIN AD YLSsENN OD\").split(\" \");" fullword ascii
    $s3  = "var BY = true  , FmPr = dQR[7] + \"\" + dQR[9];" fullword ascii
    $s4  = "return BlTiHhZ[0] + BlTiHhZ[2] + BlTiHhZ[4] + \".F\" + BlTiHhZ[7] + BlTiHhZ[9] + BlTiHhZ[12] + BlTiHhZ[14];" fullword ascii
    $s5  = "vbDMt.open(TnVav,aofMX,false);" fullword ascii
    $s6  = "var BlTiHhZ = \"Sc WkiBzyr r sRnHCwlmf ipting QerlPxT jMH ile UoRqqQLGUgUkih System Et cuHfd Obj MOXVOT ect xSzVxsO\".split(\" " ascii
    $s7  = "if (NoxWB > 185385-769){return true;} else {return false;}" fullword ascii
    $s8  = "function gSxXwed(jmQv) {" fullword ascii
    $s9  = "function IExO(ObVNU,gQyuo) {" fullword ascii
    $s10 = "return Flmyy;" fullword ascii
    $s11 = "function meeo(TLIam) {" fullword ascii
    $s12 = "function aOTh(PJqLE) {" fullword ascii
    $s13 = "return JyNkF.status;" fullword ascii
    $s14 = "function DjgJ(lDODS) {" fullword ascii
    $s15 = "return rY.ExpandEnvironmentStrings(PXWKH[6]);" fullword ascii
    $s16 = "function pAmhjboGq(DEEhebkhlQx) {" fullword ascii
    $s17 = "return QvQgUiW" fullword ascii
    $s18 = "function OsKh(NoxWB) {" fullword ascii
    $s19 = "function tjxwTDt(mmvX) {" fullword ascii
    $s20 = "function RlXd(PYcGc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}