rule sig_20160323_177dfb0c19e715ebe770772158917352 {
  meta:
    description = "datamaliciousorder - file 20160323_177dfb0c19e715ebe770772158917352.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6845ae00e23d6e0f995ac642daad2764532cf9121482c10c9c0269923666bb7c"

  strings:
    $s1  = "return WScript.CreateObject(MfVfB);" fullword ascii
    $s2  = "return igfKdQT[0] + igfKdQT[2] + igfKdQT[4] + \".F\" + igfKdQT[7] + igfKdQT[9] + igfKdQT[12] + igfKdQT[14];" fullword ascii
    $s3  = "var jh = true  , IJbk = JMf[7] + JMf[9] + JMf[11];" fullword ascii
    $s4  = "rekt.open(XqqmU,PYRRw,false);" fullword ascii
    $s5  = "var igfKdQT = RTxzW(FCwWtBublu+\" \"+\"System EJ NEQKN Obj DmtXhu ect eDhVoRD SYDMB\", \" \");" fullword ascii
    $s6  = "var JMf = (\"2.XMLHTTP ropVeQE JGljA XML ream St kZGjxudQ AD aoajoBl O xMGP D\").split(\" \");" fullword ascii
    $s7  = "function XuHT(UzWPD,PYRRw,XqqmU) {" fullword ascii
    $s8  = "function gUYEWDql(doJ) {" fullword ascii
    $s9  = "function KGaL(CGDqM,aAMiV) {" fullword ascii
    $s10 = "function TPEJ(rncWn) {" fullword ascii
    $s11 = "function csCTrGX(bqzN,anTya) {" fullword ascii
    $s12 = "if (rncWn > 162444-488){return true;} else {return false;}" fullword ascii
    $s13 = "function BcnqxugT(neJu) {" fullword ascii
    $s14 = "function ejXdn(tRNndR) {" fullword ascii
    $s15 = "function pHUs(xdTcO) {" fullword ascii
    $s16 = "function BkbRI(KaBHPi) {" fullword ascii
    $s17 = "function VNcTwAIWZ(BhbscDjMCNx) {" fullword ascii
    $s18 = "return xSLhv.status;" fullword ascii
    $s19 = "return new ActiveXObject(lSbl);" fullword ascii
    $s20 = "function GwAX(HQVWh,WVvCP) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}