rule sig_20160527_0adf338ea79f3fd21220718683fdba44 {
  meta:
    description = "datamaliciousorder - file 20160527_0adf338ea79f3fd21220718683fdba44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b8b831f62f45fba6dc9ddc5ccd9a1b4414b9ac68ab98c66edf33e3c68c9da3c"

  strings:
    $s1  = "function bLluxLbg() {return WScript;}function DHMRfPrncCiJIo(){return DxgKUg.ExpandEnvironmentStrings(BLIGJclxxZgJA())}" fullword ascii
    $s2  = "function BsfQCRyZfwpezX(jVkWgSlcdmNGiQqSC,nBMKxdqVAj){return jVkWgSlcdmNGiQqSC.charAt(nBMKxdqVAj);}" fullword ascii
    $s3  = "function BLIGJclxxZgJA(){return gZRTsslriW(JWRIpvzXNllYg[8],[1,5,7],JWRIpvzXNllYg[9]);}" fullword ascii
    $s4  = "function VKhkuQbzExSibX(){return gZRTsslriW(JWRIpvzXNllYg[10],[2,4,8,10],JWRIpvzXNllYg[11]);}" fullword ascii
    $s5  = "function zUQJEjQImR(cOFBCDJpOIeGEC,dQdhvOpDJw) {var PgumDIHwKMDU=[JWRIpvzXNllYg[15]];cOFBCDJpOIeGEC[PgumDIHwKMDU[0]](dQdhvOpDJw," ascii
    $s6  = "kluTc=0;WTUkluTc<NOTpYSUqp.length;WTUkluTc++) {bbnllhCje+=konEXntneG[NOTpYSUqp[WTUkluTc]];}return bbnllhCje.substring(3,bbnllhCj" ascii
    $s7  = "yNFjeP(NXIIGKznvBWFgtAlsOf, gltCorBC, WEjZraG);} while (JTaUeumaRuTGyxeXMxQpF < ZqKgYOuewuYyG.length);return RbmoQye;}" fullword ascii
    $s8  = "var wITFXgmEMK = QSPGFJBQ.createtextfile(DxgKUg.ExpandEnvironmentStrings(JWRIpvzXNllYg[2]+JWRIpvzXNllYg[3])+String.fromCharCode(" ascii
    $s9  = "var DxgKUg=function(){return bLluxLbg().CreateObject(JWRIpvzXNllYg[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s10 = "function gZRTsslriW(qkhmV,NOTpYSUqp,meQFqArkGasVoJ){konEXntneG=qkhmV.split(meQFqArkGasVoJ);bbnllhCje = JWRIpvzXNllYg[14];for(WTU" ascii
    $s11 = "function zUQJEjQImR(cOFBCDJpOIeGEC,dQdhvOpDJw) {var PgumDIHwKMDU=[JWRIpvzXNllYg[15]];cOFBCDJpOIeGEC[PgumDIHwKMDU[0]](dQdhvOpDJw," ascii
    $s12 = "function cn(qgTdJDbnX){return String.fromCharCode(qgTdJDbnX);}" fullword ascii
    $s13 = "function LoeVDZUBMyNFjeP(JVWshOOBuscpXFtuYzoGaEyO,IQoGYYcPHXaKXvTCTqiW,ieuuEcLUplOooGF){return String.fromCharCode(JVWshOOBuscpX" ascii
    $s14 = "var QSPGFJBQ=function(){return new ActiveXObject(JWRIpvzXNllYg[0]);}();" fullword ascii
    $s15 = "function gZRTsslriW(qkhmV,NOTpYSUqp,meQFqArkGasVoJ){konEXntneG=qkhmV.split(meQFqArkGasVoJ);bbnllhCje = JWRIpvzXNllYg[14];for(WTU" ascii
    $s16 = "function IXrxAYFrLmomSY(){return gZRTsslriW(JWRIpvzXNllYg[12],[0,3,6],JWRIpvzXNllYg[13]);}" fullword ascii
    $s17 = "92)+JWRIpvzXNllYg[4],true);" fullword ascii
    $s18 = "function LoeVDZUBMyNFjeP(JVWshOOBuscpXFtuYzoGaEyO,IQoGYYcPHXaKXvTCTqiW,ieuuEcLUplOooGF){return String.fromCharCode(JVWshOOBuscpX" ascii
    $s19 = "function tdaqPa(QUqqcEZxGUjyRfrCpeyGn,aOUGEJWgkzIZsBUN){return QUqqcEZxGUjyRfrCpeyGn.indexOf(aOUGEJWgkzIZsBUN);}" fullword ascii
    $s20 = "push(\"t\");GEoRtGfBTcAmCZ.push(\"u\");GEoRtGfBTcAmCZ.push(\"v\");GEoRtGfBTcAmCZ.push(\"w\");GEoRtGfBTcAmCZ.push(\"x\");GEoRtGfB" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}