rule sig_20160523_f9f18f8e5586165eba243668df76af2a {
  meta:
    description = "datamaliciousorder - file 20160523_f9f18f8e5586165eba243668df76af2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c721469aae9e5e55035149aa56e2e52082d16dd055275e7bcdf6943d96e8431"

  strings:
    $s1  = "function uosTJgIWet(VoehpMHZ,BImcRTRUXMUG) {VoehpMHZ.Run(BImcRTRUXMUG, 0x1, 0x0);}" fullword ascii
    $s2  = "function DUhgsyJZ(kzumM) {var JGqaolkH=ZJPjDoIQBmGiXmVIdhtdqhN[13];for(var YBtKY=0;YBtKY<kzumM;YBtKY++){tPQch+=JGqaolkH.charAt(M" ascii
    $s3  = "function DUhgsyJZ(kzumM) {var JGqaolkH=ZJPjDoIQBmGiXmVIdhtdqhN[13];for(var YBtKY=0;YBtKY<kzumM;YBtKY++){tPQch+=JGqaolkH.charAt(M" ascii
    $s4  = "ath.floor(Math.random()*JGqaolkH.length));}return tPQch;}" fullword ascii
    $s5  = "function gqiR(UCwQUn,pxkJEKw){AHcI = ZJPjDoIQBmGiXmVIdhtdqhN[10].split(ZJPjDoIQBmGiXmVIdhtdqhN[11]);pxkJEKw.open(AHcI[0]+AHcI[2]" ascii
    $s6  = "function pvzBv(qChtYafg,YEPjvy,byUvizAFb){ZEybD=qChtYafg.split(byUvizAFb);IVpJRla = ZJPjDoIQBmGiXmVIdhtdqhN[12];for(jSPZbajT=0;j" ascii
    $s7  = "function ZKmvBik() {var JEpM=100000;var MhMDXI = 100;return cZsNLFu()*(JEpM-MhMDXI)+MhMDXI;}" fullword ascii
    $s8  = "function XUIU(TUGYMD) {TUGYMD.open();}" fullword ascii
    $s9  = "function HRxb(zfaFzVu,XUdFHuW) {zfaFzVu.saveToFile(XUdFHuW, 2);}" fullword ascii
    $s10 = "function eOlsQXe(InmlL) {InmlL.close();}" fullword ascii
    $s11 = "function tVJPV(OcNbjC){return new ActiveXObject(OcNbjC);}" fullword ascii
    $s12 = "function cZsNLFu(){return Math.random();}" fullword ascii
    $s13 = "function jaIGGig(bqQj,fqiIP) {bqQj.write(fqiIP);}" fullword ascii
    $s14 = "function iRKXY(QAytMZTV,rAFMR,UHuWyyZSgc){XUIU(QAytMZTV);xlooGLKR(QAytMZTV);jaIGGig(QAytMZTV,rAFMR);lXUDhsNvI(QAytMZTV);HRxb(QAy" ascii
    $s15 = "+AHcI[3], UCwQUn, false);pxkJEKw.send();}" fullword ascii
    $s16 = "function pvzBv(qChtYafg,YEPjvy,byUvizAFb){ZEybD=qChtYafg.split(byUvizAFb);IVpJRla = ZJPjDoIQBmGiXmVIdhtdqhN[12];for(jSPZbajT=0;j" ascii
    $s17 = "function iRKXY(QAytMZTV,rAFMR,UHuWyyZSgc){XUIU(QAytMZTV);xlooGLKR(QAytMZTV);jaIGGig(QAytMZTV,rAFMR);lXUDhsNvI(QAytMZTV);HRxb(QAy" ascii
    $s18 = "function gqiR(UCwQUn,pxkJEKw){AHcI = ZJPjDoIQBmGiXmVIdhtdqhN[10].split(ZJPjDoIQBmGiXmVIdhtdqhN[11]);pxkJEKw.open(AHcI[0]+AHcI[2]" ascii
    $s19 = "function lXUDhsNvI(gEPTyk) {var ItfZAnnMof=[];gEPTyk.position=ItfZAnnMof.length*(4474753-189);}" fullword ascii
    $s20 = "function xlooGLKR(gdMFtsEwu) {gdMFtsEwu.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x0227 and
    8 of them
}