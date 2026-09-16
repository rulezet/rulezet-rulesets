rule sig_20160404_6c3ba84121f2e326b4d63d102c5421df {
  meta:
    description = "datamaliciousorder - file 20160404_6c3ba84121f2e326b4d63d102c5421df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50f33ba9634c7cc07c919469b81c88d9b5378e97cd9dd2972c83ff1f9a0e5d4e"

  strings:
    $s1  = "return VMUXvYB[0] + VMUXvYB[2] + VMUXvYB[4] + \".F\" + VMUXvYB[7] + VMUXvYB[9] + VMUXvYB[12] + VMUXvYB[14];" fullword ascii
    $s2  = "var Pw = true  , kkbo = Gee[7] + Gee[9] + Gee[11];" fullword ascii
    $s3  = "VnEU.open(zgQoN,eYBhq,false);" fullword ascii
    $s4  = "var Gee = (\"2.XMLHTTP zxZOOxO VfMOC XML ream St deCFDtYm AD hvZrIwc O FqEK D\").split(\" \");" fullword ascii
    $s5  = "var VMUXvYB = merUM(EpzvxuufdX+\" \"+\"System at NzNCq Obj qEVrNY ect IPQRdnh HSUDh\", \" \");" fullword ascii
    $s6  = "function OlZwgOWrj(eNWmo) {" fullword ascii
    $s7  = "if(v>=x.length) {break;}" fullword ascii
    $s8  = "function pydS(GBTsZ,wMllq) {" fullword ascii
    $s9  = "if (TfkxH == 1123-923){return true;} else {return false;}" fullword ascii
    $s10 = "function MRwe(YBobD,MXrVx) {" fullword ascii
    $s11 = "function dUrf(BFjdh) {" fullword ascii
    $s12 = "return WZL.split(ZZjti);" fullword ascii
    $s13 = "function rNDYT(KxtYOc) {" fullword ascii
    $s14 = "function merUM(WZL,ZZjti) {" fullword ascii
    $s15 = "function fipK(zOyIX) {" fullword ascii
    $s16 = "function ijTQ(JnRiP) {" fullword ascii
    $s17 = "function DumTAn(CXSnUtK) {" fullword ascii
    $s18 = "XtX = v; break; " fullword ascii
    $s19 = "return WVu.size;" fullword ascii
    $s20 = "return clsY[xsPiqM[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}