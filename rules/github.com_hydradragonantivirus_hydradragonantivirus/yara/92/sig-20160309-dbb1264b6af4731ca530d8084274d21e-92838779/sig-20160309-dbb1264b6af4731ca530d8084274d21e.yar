rule sig_20160309_dbb1264b6af4731ca530d8084274d21e {
  meta:
    description = "datamaliciousorder - file 20160309_dbb1264b6af4731ca530d8084274d21e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "400bf2c8a10e8e1f37bc1c4565984ea8a987f460909e0864e23317632d5ece3e"

  strings:
    $s1  = "return zpvIlRG[0] + zpvIlRG[2] + zpvIlRG[4] + \".F\" + zpvIlRG[7] + zpvIlRG[9] + zpvIlRG[12] + zpvIlRG[14];" fullword ascii
    $s2  = "var En = true  , QFyc = FAP[7] + FAP[9] + FAP[11];" fullword ascii
    $s3  = "var zpvIlRG = \"Sc mesBFGU r csSGwrlAm ipting MYSGxik Iwu ile sEavuxhuEdzEIN System LL IwLEJ Obj gWWGYL ect DIYaIhC\".split(\" " ascii
    $s4  = "nGEVK.open(iFJfC,cnwdA,false);" fullword ascii
    $s5  = "var FAP = (\"2.XMLHTTP SDaEDtN LaxwB XML ream St EyXQxGgC AD tscvAXf O pFgJ D\").split(\" \");" fullword ascii
    $s6  = "return jVkl.ExpandEnvironmentStrings(rAVbL);" fullword ascii
    $s7  = "function FwxH(EcdpD) {" fullword ascii
    $s8  = "if(w>=b.length) {break;}" fullword ascii
    $s9  = "return new ActiveXObject(lgYrnT);" fullword ascii
    $s10 = "function PblRtrStu(waHaRTLpEHh) {" fullword ascii
    $s11 = "function YXIEbsf(jVkl,rAVbL) {" fullword ascii
    $s12 = "function wyueqmpi(Dia) {" fullword ascii
    $s13 = "function etsV(pWzmG,lJLAn) {" fullword ascii
    $s14 = "function pNyxnblq(fSUBX,JWVcdw) {" fullword ascii
    $s15 = "return Dia.size;" fullword ascii
    $s16 = "function eFRj(UpTzY,CdzNF) {" fullword ascii
    $s17 = "function vOYm(Xwfgy) {" fullword ascii
    $s18 = "function AlVmPMUp() {" fullword ascii
    $s19 = "return zRNdEkc" fullword ascii
    $s20 = "if (Xwfgy > 165629-732){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}