rule sig_20160301_1bd26373b007c7077f313b136d08ae72 {
  meta:
    description = "datamaliciousorder - file 20160301_1bd26373b007c7077f313b136d08ae72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c2afc20c3d67a45ca37003bbbf9ec2b2af7325becb4150949c26a71bb772be6"

  strings:
    $s1  = "var BK = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(CGtsb);" fullword ascii
    $s3  = "function FtpWZ(eYWZls) {" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + KkAGiva + \".F\" + SgBvBXsKct + ddeWF + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var Ba = true  , vvZt = qwC[7] + \"\" + qwC[9];" fullword ascii
    $s6  = "var qwC = (XBp + \"TTP\" + \" xkcOEbg fuWeh XML ream St CEqfayQg AD kzXzNOE OD\").split(\" \");" fullword ascii
    $s7  = "rQxSw.open(wjliZ,INnjC,false);" fullword ascii
    $s8  = "if (omHPi > 188709-726){return true;} else {return false;}" fullword ascii
    $s9  = "return new ActiveXObject(eYWZls);" fullword ascii
    $s10 = "function gCSC(omHPi) {" fullword ascii
    $s11 = "if(Q>=v.length) {break;}" fullword ascii
    $s12 = "function nuwm(JsYJQ,xDpWT) {" fullword ascii
    $s13 = "function cEjH(Dlegw) {" fullword ascii
    $s14 = "function yZUfgNFA() {" fullword ascii
    $s15 = "function hSUe(CGtsb) {" fullword ascii
    $s16 = "function uTeO(mcbzE) {" fullword ascii
    $s17 = "return WT.ExpandEnvironmentStrings(BK);" fullword ascii
    $s18 = "function ZUFA(rQxSw,INnjC,wjliZ) {" fullword ascii
    $s19 = "function GhlnoyGkQ(ONYeHkyrFSW) {" fullword ascii
    $s20 = "if (mcbzE == 762-562){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}