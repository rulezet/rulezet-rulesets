rule sig_20160301_d7e5f10b1970169931a634110d6e7e50 {
  meta:
    description = "datamaliciousorder - file 20160301_d7e5f10b1970169931a634110d6e7e50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97292dc1412cdcb69c0d00e651be06c0838b58a48fb3baa6796030c26067fcfc"

  strings:
    $s1  = "var CX = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(ZHBsT);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + hKfnDyD + \".F\" + sESFWHJPUJ + IjYkF + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var ld = true  , zuxM = iEF[7] + \"\" + iEF[9];" fullword ascii
    $s5  = "var iEF = (gnf + \"TTP\" + \" SMsNgQB cPqWB XML ream St ehcPtWII AD uENWeUu OD\").split(\" \");" fullword ascii
    $s6  = "TmQdO.open(tssEp,yybLU,false);" fullword ascii
    $s7  = "if (((new Date())>0,7513496888)) {" fullword ascii
    $s8  = "return qWaXo.status;" fullword ascii
    $s9  = "function VvsB(CUhyM) {" fullword ascii
    $s10 = "function Wkhq(TmQdO,yybLU,tssEp) {" fullword ascii
    $s11 = "function Mebs(qWaXo) {" fullword ascii
    $s12 = "function Refh(ZHBsT) {" fullword ascii
    $s13 = "function vegFS(iXgBtO) {" fullword ascii
    $s14 = "return new ActiveXObject(iXgBtO);" fullword ascii
    $s15 = "return Rg.ExpandEnvironmentStrings(CX);" fullword ascii
    $s16 = "function AMmf(RRguC,tdUeb) {" fullword ascii
    $s17 = "function ioSh(obnTc) {" fullword ascii
    $s18 = "if (ZYXxq == 360-160){return true;} else {return false;}" fullword ascii
    $s19 = "gzR = a; break; " fullword ascii
    $s20 = "function ICNJ(mJQqb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}