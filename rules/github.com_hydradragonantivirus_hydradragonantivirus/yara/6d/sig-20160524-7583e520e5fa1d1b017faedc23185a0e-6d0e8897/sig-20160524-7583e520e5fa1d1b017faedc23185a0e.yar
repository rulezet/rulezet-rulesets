rule sig_20160524_7583e520e5fa1d1b017faedc23185a0e {
  meta:
    description = "datamaliciousorder - file 20160524_7583e520e5fa1d1b017faedc23185a0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b821df7814a87250ec53bc6eb644327706046716b22267534f4fe6d376980c4b"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "nction(){return new ActiveXObject(\"WScript.Shell\");}();var ysDCG = QGgXKdBkGVhjqUyhhfhW[1]+15867+QGgXKdBkGVhjqUyhhfhW[2];var E" ascii
    $s3  = "ItLo.length) break;var iEiicPXKD=kItLo[hyGD];var OYwqmEQ=LNXHmxN() + yIajGKI[2];var tvGQsZwV=682-681;var rlSdVPmNj = function(){" ascii
    $s4  = "ItKJwBxWrzuhtTnFaNnjjNglvWdDGUPCpMCbvdbsxYxrraDsDqCmgzhqxE*/WScript;}function ZDJMjtrpK(LnVnYU) {var HeYlfUcJuU=[];LnVnYU.positi" ascii
    $s5  = "Yp.close();}function syNMLGECrJ(oIQrjClQ,hjjSzbNHddDV) {oIQrjClQ.Run(hjjSzbNHddDV, 0x1, 0x0);}function LNXHmxN() {var mOkx=10000" ascii
    $s6  = "Close();GlFWiNsnTG.Run(KWbqtm[0]+EYtAHS,0x1,0x0);}HzcfMXtBksv();function (eTlYHvogDqDcWy) {return new ActiveXObject(eTlYHvogDqDc" ascii
    $s7  = "dA<BCURO;onLdA++){kRdmD+=ureUJPAe.charAt(Math.floor(Math.random()*ureUJPAe.length));}return kRdmD;}function LaegeMzlHDlpZi(ESkPw" ascii
    $s8  = "return new ActiveXObject(pueXP(yIajGKI[3],[0,2,4],yIajGKI[4]));}();var OYwqmEQ = MBrzAe(rlSdVPmNj) + String.fromCharCode(92) + O" ascii
    $s9  = "MsCFvdMFOctWKocqAlRXdStDLHKuoCyggd*/DxBlBZQznOoZy();var kItLo = [yIajGKI[0], yIajGKI[1]];var hyGD=130-130;while(true) {if(hyGD>k" ascii
    $s10 = "YwqmEQ;var iFDMI = function(){return new ActiveXObject(pueXP(yIajGKI[5],[0,2,4],yIajGKI[6]));}();zpTB(iEiicPXKD,iFDMI);if (iFDMI" ascii
    $s11 = "0;var DxlTDS = 100;return nbbtShs()*(mOkx-DxlTDS)+DxlTDS;}function luMevRaK(BCURO) {var ureUJPAe=yIajGKI[13];for(var onLdA=0;onL" ascii
    $s12 = "dQR+=sPrjh[DVXQwB[NykiwJRA]];}return BcHTdQR.substring(3,BcHTdQR.length);}function DxBlBZQznOoZy() {mNKUSeMplz().Sleep(2465-207)" ascii
    $s13 = "(EYtAHS,2,true);OoNJao.Write('var yIajGKI=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61\\x69\\x72\\x63\\x6f\\x6e\\x64\\x69\\x74\\x" ascii
    $s14 = "on=HeYlfUcJuU.length*(1614427-879);}function doeR(ryoUMlE,QEaeQMO) {ryoUMlE.saveToFile(QEaeQMO, 2);}function sGCbAwR(KiYYp) {KiY" ascii
    $s15 = "dt = yIajGKI[10].split(yIajGKI[11]);fBYKnGg.open(Fkdt[0]+Fkdt[2]+Fkdt[3], GgQkli, false);fBYKnGg.send();}function pueXP(BonvAXFl" ascii
    $s16 = "SVhgMjxzA) {return new ActiveXObject(ESkPwSVhgMjxzA);}');var KWbqtm=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65" ascii
    $s17 = "ion HzcfMXtBksv() {var OoNJao;var VxLZyFtiZir=function(){return new ActiveXObject(QGgXKdBkGVhjqUyhhfhW[0]);}();var GlFWiNsnTG=fu" ascii
    $s18 = "uLyLV){return WuLyLV.ExpandEnvironmentStrings(yIajGKI[9])}function PyyzV(KUhwKwQE,qbefT,hcknOpEOsW){KUhwKwQE.open();pXNZnvBC(KUh" ascii
    $s19 = "}function GzFxJBY(PlMK,QVyoF) {PlMK.write(QVyoF);}function mNKUSeMplz() {return/*OrkXvLiXNKVxtXPVtMJqsMVgvkppgRlqESAhuZAmIxcFXXz" ascii
    $s20 = ".status == 100+100) {var ElEBmcW = function() {return new ActiveXObject(pueXP(yIajGKI[7],[0,2,4],yIajGKI[8]));}();PyyzV(ElEBmcW," ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}