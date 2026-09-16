rule sig_20160322_39f88bc7c0ff8d0eee455ff8fb711c3e {
  meta:
    description = "datamaliciousorder - file 20160322_39f88bc7c0ff8d0eee455ff8fb711c3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867aba839d50567a88f63df6e989e907f5477a58710bb3e1a50a56ee8055cb85"

  strings:
    $s1  = "return WScript.CreateObject(yLaYY);" fullword ascii
    $s2  = "var je = true  , XUSN = bNU[7] + bNU[9] + bNU[11];" fullword ascii
    $s3  = "return sLexdGv[0] + sLexdGv[2] + sLexdGv[4] + \".F\" + sLexdGv[7] + sLexdGv[9] + sLexdGv[12] + sLexdGv[14];" fullword ascii
    $s4  = "var bNU = (\"2.XMLHTTP uikissQ EBAsx XML ream St MhygblVs AD MikKEOg O CntA D\").split(\" \");" fullword ascii
    $s5  = "FmCwO.open(AeqrQ,RwHlT,false);" fullword ascii
    $s6  = "var sLexdGv = vCJEv(WsXQRuIoXr+\" \"+\"System nY mamIk Obj hbzAwQ ect MuuySZQ TWYeX\", \" \");" fullword ascii
    $s7  = "QHdk(TO,kQEJZ+q[s]+k, dSL[12]+dSL[14]+dSL[16]); oPAH(TO); " fullword ascii
    $s8  = "return LTe.size;" fullword ascii
    $s9  = "function JOYz(rMUzE,YbScZ) {" fullword ascii
    $s10 = "StC = s; break; " fullword ascii
    $s11 = "function NyDymdcH(LTe) {" fullword ascii
    $s12 = "if (J >= YwIQy.length) {break;}" fullword ascii
    $s13 = "function fSPI(ZTdVI) {" fullword ascii
    $s14 = "function NfTJWEq(LsCz) {" fullword ascii
    $s15 = "function qpqlNzE(UBAC,RidAA) {" fullword ascii
    $s16 = "function rwJFO(jtAFlU) {" fullword ascii
    $s17 = "function FoAu(xcPcj) {" fullword ascii
    $s18 = "return UBAC.ExpandEnvironmentStrings(RidAA);" fullword ascii
    $s19 = "function EAuH(tHrAm,FsRXj) {" fullword ascii
    $s20 = "return Qwtvt;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}