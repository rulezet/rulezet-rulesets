rule sig_20160321_7853dc9b7fbe2e92f75539853f365202 {
  meta:
    description = "datamaliciousorder - file 20160321_7853dc9b7fbe2e92f75539853f365202.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8f4193e100fef2cdf0f0c81d63181efa3bb68cf828a266fb5636451e28a4f7f"

  strings:
    $s1  = "return WScript.CreateObject(mNlpS);" fullword ascii
    $s2  = "return mDFOMVq[0] + mDFOMVq[2] + mDFOMVq[4] + \".F\" + mDFOMVq[7] + mDFOMVq[9] + mDFOMVq[12] + mDFOMVq[14];" fullword ascii
    $s3  = "var tv = true  , ijlQ = cUf[7] + cUf[9] + cUf[11];" fullword ascii
    $s4  = "var cUf = (\"2.XMLHTTP xPiFbPV sYYUh XML ream St vSthBMtg AD fozWdSC O QYrR D\").split(\" \");" fullword ascii
    $s5  = "var mDFOMVq = hGrpO(MGwiyZTTCV+\" \"+\"System zR IcieN Obj bUAemg ect WWKEHKi CHyEj\", \" \");" fullword ascii
    $s6  = "XRBHJ.open(yuwkk,eYtuU,false);" fullword ascii
    $s7  = "if(T>=X.length) {break;}" fullword ascii
    $s8  = "function imBW(JNrtc) {" fullword ascii
    $s9  = "function dgsJ(MYMnl,CXGkH) {" fullword ascii
    $s10 = "function yqNu(zjYoR) {" fullword ascii
    $s11 = "return OEq.size;" fullword ascii
    $s12 = "function QAMXX(zttuQJ) {" fullword ascii
    $s13 = "return ABmY.ExpandEnvironmentStrings(cDppo);" fullword ascii
    $s14 = "function hGrpO(EZd,RHfLI) {" fullword ascii
    $s15 = "return zttuQJ.position=111-111;" fullword ascii
    $s16 = "function wYAI(aSSUx) {" fullword ascii
    $s17 = "function fLuD(HJfLd) {" fullword ascii
    $s18 = "function sNOdu(CbmQvd) {" fullword ascii
    $s19 = "function OpSvYrsL(NsIh) {" fullword ascii
    $s20 = "return sJvLX;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}