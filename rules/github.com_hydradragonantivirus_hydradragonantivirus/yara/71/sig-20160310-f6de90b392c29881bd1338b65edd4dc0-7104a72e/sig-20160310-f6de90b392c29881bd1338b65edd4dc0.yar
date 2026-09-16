rule sig_20160310_f6de90b392c29881bd1338b65edd4dc0 {
  meta:
    description = "datamaliciousorder - file 20160310_f6de90b392c29881bd1338b65edd4dc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bae50a70181cda8d1a3b12c7b18bc3297c83e9be65a471844965082e7304e69b"

  strings:
    $s1  = "function rAmkzFtpN(vyplkSuMSFD) {" fullword ascii
    $s2  = "return iYAceuL[0] + iYAceuL[2] + iYAceuL[4] + \".F\" + iYAceuL[7] + iYAceuL[9] + iYAceuL[12] + iYAceuL[14];" fullword ascii
    $s3  = "var UR = true  , Bgjx = Fnb[7] + Fnb[9] + Fnb[11];" fullword ascii
    $s4  = "fkWqU.open(UXogC,gBKJd,false);" fullword ascii
    $s5  = "var Fnb = (\"2.XMLHTTP zzQGkMW xtBHY XML ream St nZGmqzOb AD OSvrDnc O qwnd D\").split(\" \");" fullword ascii
    $s6  = "var iYAceuL = \"Sc klaOvrK r XoXXCwKRY ipting kDgFSMx QWv ile NvSogxBHpQaWNd System Ue RaInU Obj SDMCZm ect JwsKUqL\".split(\" " ascii
    $s7  = "if(r>=A.length) {break;}" fullword ascii
    $s8  = "function zcXH(iZudG) {" fullword ascii
    $s9  = "function mezS(BVCNV) {" fullword ascii
    $s10 = "return GFQND;" fullword ascii
    $s11 = "return iVaktix" fullword ascii
    $s12 = "if (F >= vaHuP.length) {break;}" fullword ascii
    $s13 = "function rrVs(vaHuP) {" fullword ascii
    $s14 = "return new ActiveXObject(IoVMpE);" fullword ascii
    $s15 = "function aOHf(uKjlM) {" fullword ascii
    $s16 = "function iMya(rOeVY) {" fullword ascii
    $s17 = "function GwaU(fkWqU,gBKJd,UXogC) {" fullword ascii
    $s18 = "return BVCNV.status;" fullword ascii
    $s19 = "if (iZudG == 329-129){return true;} else {return false;}" fullword ascii
    $s20 = "return YwTm.ExpandEnvironmentStrings(iORld);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}