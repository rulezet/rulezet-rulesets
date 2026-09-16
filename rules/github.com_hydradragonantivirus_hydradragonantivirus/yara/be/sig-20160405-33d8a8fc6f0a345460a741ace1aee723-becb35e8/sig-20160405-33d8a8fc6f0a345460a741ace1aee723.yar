rule sig_20160405_33d8a8fc6f0a345460a741ace1aee723 {
  meta:
    description = "datamaliciousorder - file 20160405_33d8a8fc6f0a345460a741ace1aee723.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea09324c5dbd1d0b7ced93f5036e4937b80073bd460de31405a947004360ffbe"

  strings:
    $s1  = "return YndlEXu[0] + YndlEXu[2] + YndlEXu[4] + \".F\" + YndlEXu[7] + YndlEXu[9] + YndlEXu[12] + YndlEXu[14];" fullword ascii
    $s2  = "var Dc = true  , zhCM = RCR[7] + RCR[9] + RCR[11];" fullword ascii
    $s3  = "var RCR = (\"2.XMLHTTP JrzOATV zZnoZ XML ream St nmngRPXb AD zAwLlSw O VlpI D\").split(\" \");" fullword ascii
    $s4  = "spSS.open(YtWKE,GoAlu,false);" fullword ascii
    $s5  = "if (WsoFX == 955-755){return true;} else {return false;}" fullword ascii
    $s6  = "ZBL = Q; break; " fullword ascii
    $s7  = "if(Q>=q.length) {break;}" fullword ascii
    $s8  = "function JdJHK(nlB,wtxuW) {" fullword ascii
    $s9  = "return xXszuhf(Qw,hYNHE[287-281]+hYNHE[196-189]+hYNHE[373-365]);" fullword ascii
    $s10 = "return znLGXJf;" fullword ascii
    $s11 = "function iIPy(WsoFX) {" fullword ascii
    $s12 = "return tOx.size;" fullword ascii
    $s13 = "function ajZtbyd(AWFE) {" fullword ascii
    $s14 = "function tHfSXO(RNhLQuC) {" fullword ascii
    $s15 = "if (cYpCk > 151919-964){return true;} else {return false;}" fullword ascii
    $s16 = "return \"xlnbQGXrtrNDHk\";" fullword ascii
    $s17 = "function kMMEj(rzqPup) {" fullword ascii
    $s18 = "function jziA(FeeLp) {" fullword ascii
    $s19 = "if (o >= FeeLp.length) {break;}" fullword ascii
    $s20 = "function uxzQORQRe(YpCsZpTNqax) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}