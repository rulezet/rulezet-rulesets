rule sig_20160524_8b0671cb0e4fdca951a2aabfd6f07aec {
  meta:
    description = "datamaliciousorder - file 20160524_8b0671cb0e4fdca951a2aabfd6f07aec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab81ff583de0e6eee2d39830d1809cddbbb7fda1e559e70212ae3476c223a035"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "kgHsejNmc[0]);}();var oGiRnMMECRaGtk=function(){return new ActiveXObject(\"WScript.Shell\");}();var KRlGxKdd = rKkgHsejNmc[1]+10" ascii
    $s3  = ";}function mbQuKty(neRCd) {neRCd.close();}function MVgaABPQMj(IJnRqsxX,ScfASyFYxRPp) {IJnRqsxX.Run(ScfASyFYxRPp, 0x1, 0x0);}func" ascii
    $s4  = "xOnTHkCGVFxZnGLphrDwArKKRLsXgdmCPzErSEeGMvYoxFZHwmqDIVJuFLqXmmXEbENiWrAawFuXzYgtEBWeJSCx*/WScript;}function MzqFIPAJD(zmNvij) {v" ascii
    $s5  = ";var AGRdBpd = ZvuuPL(VaMxJlaCS) + String.fromCharCode(92) + AGRdBpd;var OHtQm = function(){return new ActiveXObject(tAott(XPHJg" ascii
    $s6  = "224;while(true) {if(lSio>zNBVE.length) break;var vgiJAtfox=zNBVE[lSio];var AGRdBpd=ghiYHMP() + XPHJgsjYyEgQYCNvtGt[2];var KUmjkD" ascii
    $s7  = "neCPv.length;ytHHdDGA++) {ZOjwJGW+=fOQxx[cneCPv[ytHHdDGA]];}return ZOjwJGW.substring(3,ZOjwJGW.length);}function meiqlOBZgcQtU()" ascii
    $s8  = ";PJOPCuf(lcibJKdV,fkaCc);MzqFIPAJD(lcibJKdV);wfrY(lcibJKdV,lsvHbXxxpg);mbQuKty(lcibJKdV);}function hDoL(xFIfTH,Kerpfbr){GdOR = X" ascii
    $s9  = "6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function BJXKtdVIhfSAh() {var QFJzpduwW;var QUqfgRJGV=function(){return new Active" ascii
    $s10 = "eturn KcviO;}function WlXPlracvijDsI(edsqPNqfWtBzDg) {return new ActiveXObject(edsqPNqfWtBzDg);}');var MeJlOQnCcSFSLFteJGVBDxul=" ascii
    $s11 = "bU=933-932;var VaMxJlaCS = function(){return new ActiveXObject(tAott(XPHJgsjYyEgQYCNvtGt[3],[0,2,4],XPHJgsjYyEgQYCNvtGt[4]));}()" ascii
    $s12 = " {jTZYjPdXbr().Sleep(4622-468);}function ulQRRlL(){return Math.random();}function UWlX(kWfzsB) {kWfzsB.open();}function kQxXrUfV" ascii
    $s13 = "ar iHUENnohSL=[];zmNvij.position=iHUENnohSL.length*(1253208-185);}function wfrY(XjABUDm,qTaTQZK) {XjABUDm.saveToFile(qTaTQZK, 2)" ascii
    $s14 = "n() {return new ActiveXObject(tAott(XPHJgsjYyEgQYCNvtGt[7],[0,2,4],XPHJgsjYyEgQYCNvtGt[8]));}();gFayV(RrirHtg,OHtQm.ResponseBody" ascii
    $s15 = "PHJgsjYyEgQYCNvtGt[10].split(XPHJgsjYyEgQYCNvtGt[11]);Kerpfbr.open(GdOR[0]+GdOR[2]+GdOR[3], xFIfTH, false);Kerpfbr.send();}funct" ascii
    $s16 = "im.ExpandEnvironmentStrings(XPHJgsjYyEgQYCNvtGt[9])}function gFayV(lcibJKdV,fkaCc,lsvHbXxxpg){lcibJKdV.open();kQxXrUfV(lcibJKdV)" ascii
    $s17 = "zpduwW = QUqfgRJGV.OpenTextFile(cjuGEacwJRnRME,2,true);QFJzpduwW.Write('var XPHJgsjYyEgQYCNvtGt=[\"\\x68\\x74\\x74\\x70\\x3a\\x2" ascii
    $s18 = "(TjtHHISSa) {TjtHHISSa.type=1;}function PJOPCuf(suge,BpyvI) {suge.write(BpyvI);}function jTZYjPdXbr() {return/*rLQJImhEtYfnsTovU" ascii
    $s19 = "nRME,0x1,0x0);}BJXKtdVIhfSAh();function (ENTlUPKMuVKR) {return new ActiveXObject(ENTlUPKMuVKR);}" fullword ascii
    $s20 = "tion ghiYHMP() {var Tinu=100000;var aajdEb = 100;return ulQRRlL()*(Tinu-aajdEb)+aajdEb;}function zvsDGzzz(EWMfQ) {var QropMXrz=X" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}