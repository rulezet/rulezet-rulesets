rule sig_20160302_3a5de5a4acc9e740501e2e98b6843b0c {
  meta:
    description = "datamaliciousorder - file 20160302_3a5de5a4acc9e740501e2e98b6843b0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0582aeb2a2edecbfbd64dac869f96154db2f44e8f24d61a3af62564b3833eac8"

  strings:
    $s1  = "var nO = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(cylaR);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + WQneqCr + \".F\" + uaiWAZTFay + gdMmS + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var mxk = (BcJ + \"TTP\" + \" wsYrdNI BixQc XML ream St CrWtNNUu AD LoAjyQm OD\").split(\" \");" fullword ascii
    $s5  = "var Sq = true  , vBcz = mxk[7] + \"\" + mxk[9];" fullword ascii
    $s6  = "vutJK.open(cGxDe,VzbAp,false);" fullword ascii
    $s7  = "if (((new Date())>0,7466554888)) {" fullword ascii
    $s8  = "function rYSoaun(VaGr) {" fullword ascii
    $s9  = "function XERB(QvWDi) {" fullword ascii
    $s10 = "function LTQm(cylaR) {" fullword ascii
    $s11 = "function LsTcE(BuhcUf) {" fullword ascii
    $s12 = "function BViW(lIFOk) {" fullword ascii
    $s13 = "function fxwZBDhYG(xtqcP,EIBSb,WfgiZ) {" fullword ascii
    $s14 = "RFe = f; break; " fullword ascii
    $s15 = "return new ActiveXObject(BuhcUf);" fullword ascii
    $s16 = "if(f>=N.length) {break;}" fullword ascii
    $s17 = "function ZUyPCGhJ() {" fullword ascii
    $s18 = "function kJyn(JOztc,oDaPF) {" fullword ascii
    $s19 = "return vDFLY;" fullword ascii
    $s20 = "if (BuuvL == 355-155){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}