rule sig_20160229_13aafea30ff0ea7ab0693f22aa1bc230 {
  meta:
    description = "datamaliciousorder - file 20160229_13aafea30ff0ea7ab0693f22aa1bc230.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89a01955add061ddc735bc3bac47bcec14c6da6aaaf13f78cd62a108f09b3a0b"

  strings:
    $s1  = "var zK = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(EXjbN);" fullword ascii
    $s3  = "var rKV = (yng + \"TTP\" + \" KopxpjI YNeoY XML ream St sPdOQrOb AD rzIcuTc OD\").split(\" \");" fullword ascii
    $s4  = "var sp = true  , RZce = rKV[7] + \"\" + rKV[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + PiRQwTc + \".F\" + EPfJUumpGx + sUKZH + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "FPpRI.open(MXtkg,UoIZQ,false);" fullword ascii
    $s7  = "if(h>=c.length) {break;}" fullword ascii
    $s8  = "function lQWj(BoMrR) {" fullword ascii
    $s9  = "if (((new Date())>0,7448464888)) {" fullword ascii
    $s10 = "function vOjl(FPpRI,UoIZQ,MXtkg) {" fullword ascii
    $s11 = "return TKMXZ;" fullword ascii
    $s12 = "function NIwF(BsRNx,OGReG) {" fullword ascii
    $s13 = "function NMLT(UHZEQ) {" fullword ascii
    $s14 = "if (JfBRD == 864-664){return true;} else {return false;}" fullword ascii
    $s15 = "function CgWa(JfBRD) {" fullword ascii
    $s16 = "if (EoAPD > 176425-148){return true;} else {return false;}" fullword ascii
    $s17 = "return BoMrR.status;" fullword ascii
    $s18 = "function HOpGucZue(WeMHq,Bvmzy,woTkH) {" fullword ascii
    $s19 = "function HlTW(EoAPD) {" fullword ascii
    $s20 = "function MMOt(EXjbN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}