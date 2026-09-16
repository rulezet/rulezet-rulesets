rule sig_20160524_5a8ae32f8f77f1cc663524180572e86f {
  meta:
    description = "datamaliciousorder - file 20160524_5a8ae32f8f77f1cc663524180572e86f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dbbdee279d18f9fe3ffa1e47c43bcfeac353f8b9efe31107988df104fb0ad87"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "veToFile(lBKyBgj, 2);}function jxOnnrY(bWbHe) {bWbHe.close();}function TSpBrJUXcR(TwjjmEAb,xzlnyMbjNwjI) {TwjjmEAb.Run(xzlnyMbjN" ascii
    $s3  = "rn/*mtFbTAQRwVHigwaEJvvlpJQGLGJUibZIqokZwlozliKlVYxQjaXspelwXCKhtoseoDJrTpGzUPIIDVMwEYtUiSzHdTENyTFTflbcjNRTx*/WScript;}function" ascii
    $s4  = "38;while(true) {if(ARMd>ZeMED.length) break;var KMsCFvdMF=ZeMED[ARMd];var OctWKoc=xVWqzgF() + AnExmjhTdIMGlSxyJrZAd[2];var qAlRX" ascii
    $s5  = ");}();var OctWKoc = ZHAuBy(DLHKuoCyg) + String.fromCharCode(92) + OctWKoc;var HDlpZ = function(){return new ActiveXObject(gTWmi(" ascii
    $s6  = "HDQkA.send();}function gTWmi(PtgThwVb,nFKQaQ,eXKDjJkQC){ZxLRk=PtgThwVb.split(eXKDjJkQC);FHpDovA = AnExmjhTdIMGlSxyJrZAd[12];for(" ascii
    $s7  = "= function() {return new ActiveXObject(gTWmi(AnExmjhTdIMGlSxyJrZAd[7],[0,2,4],AnExmjhTdIMGlSxyJrZAd[8]));}();bGeZb(iESkPwS,HDlpZ" ascii
    $s8  = "){return dDlkbd.ExpandEnvironmentStrings(AnExmjhTdIMGlSxyJrZAd[9])}function bGeZb(aDDOdOgF,pQUsH,nDuEktBenc){aDDOdOgF.open();JzX" ascii
    $s9  = "dSt=807-806;var DLHKuoCyg = function(){return new ActiveXObject(gTWmi(AnExmjhTdIMGlSxyJrZAd[3],[0,2,4],AnExmjhTdIMGlSxyJrZAd[4])" ascii
    $s10 = "1,0x0);}JhYKSMhFvAQqe();function (MzohFZiEc) {return new ActiveXObject(MzohFZiEc);}" fullword ascii
    $s11 = "KSbplzjb=0;KSbplzjb<nFKQaQ.length;KSbplzjb++) {FHpDovA+=ZxLRk[nFKQaQ[KSbplzjb]];}return FHpDovA.substring(3,FHpDovA.length);}fun" ascii
    $s12 = "3\\x74\",\"\\x73\\x56\\x53\\x47\\x47\\x7a\\x47\\x6e\\x66\\x49\\x76\\x7a\\x7a\\x49\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d" ascii
    $s13 = "();}function JzXVtwMc(ZHfJNZcws) {ZHfJNZcws.type=1;}function OascSZd(BFvI,bRoMn) {BFvI.write(bRoMn);}function piscDbQiAG() {retu" ascii
    $s14 = "HDQkA){UOxd = AnExmjhTdIMGlSxyJrZAd[10].split(AnExmjhTdIMGlSxyJrZAd[11]);wVHDQkA.open(UOxd[0]+UOxd[2]+UOxd[3], chBsEh, false);wV" ascii
    $s15 = "Qqe() {var hUyCbITDrHa;var icBeCZrfAUDiO=function(){return new ActiveXObject(jLxRGhbtlQvBw[0]);}();var YNxmyLEmCUhY=function(){r" ascii
    $s16 = "ile(pkyGKeOtlZhix,2,true);hUyCbITDrHa.Write('var AnExmjhTdIMGlSxyJrZAd=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x61\\x67\\x6" ascii
    $s17 = "VtwMc(aDDOdOgF);OascSZd(aDDOdOgF,pQUsH);UcuxHKjpu(aDDOdOgF);VvND(aDDOdOgF,nDuEktBenc);jxOnnrY(aDDOdOgF);}function hGAP(chBsEh,wV" ascii
    $s18 = "ction PyyekWvRqIPVZ() {piscDbQiAG().Sleep(2584-481);}function dlcSewr(){return Math.random();}function XgJC(Opjypk) {Opjypk.open" ascii
    $s19 = "wjI, 0x1, 0x0);}function xVWqzgF() {var pvjE=100000;var hXxsWq = 100;return dlcSewr()*(pvjE-hXxsWq)+hXxsWq;}function OSnlAElU(yA" ascii
    $s20 = ")*dVUZnqiM.length));}return NrwNy;}function urZCTxPeNqKGpP(JNkmjFIziLwUhl) {return new ActiveXObject(JNkmjFIziLwUhl);}');var gFG" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}