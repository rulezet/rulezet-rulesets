rule sig_20160524_52e9956bff100fad8a41943d8fadb8f6 {
  meta:
    description = "datamaliciousorder - file 20160524_52e9956bff100fad8a41943d8fadb8f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bc609e9add6e36e562ebbb5ff9f1c3e567cd8912fc29e70b2a7055b58e42182"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = ");}();var xfzkXuR=function(){return new ActiveXObject(\"WScript.Shell\");}();var WHIPsLuge = XfxwkFgOayMsy[1]+12733+XfxwkFgOayMs" ascii
    $s3  = "while(true) {if(clNL>Kvfxh.length) break;var NozMqLRUn=Kvfxh[clNL];var JhZiUQy=HkMFdur() + BJxSzocigRqQSXgenEJ[2];var iBHrPsac=2" ascii
    $s4  = "NaidKkjxDIQrEmaqxolztGwyfGgqSfmHrvnBOvhETvuUSpWcxtnhTBrOSdGcERfCPkmsKZZecCRQaLMhsSij*/WScript;}function kPchgHQHh(PEVWFR) {var e" ascii
    $s5  = "nction MiCSqXh(UgmqE) {UgmqE.close();}function nlVUpFoprH(oOZclOqa,YnXoSLXcNgWd) {oOZclOqa.Run(YnXoSLXcNgWd, 0x1, 0x0);}function" ascii
    $s6  = " JhZiUQy = YFAqES(kDLCXTisi) + String.fromCharCode(92) + JhZiUQy;var FRerk = function(){return new ActiveXObject(ZaUrW(BJxSzocig" ascii
    $s7  = "RqQSXgenEJ[5],[0,2,4],BJxSzocigRqQSXgenEJ[6]));}();OrQn(NozMqLRUn,FRerk);if (FRerk.status == 100+100) {var MlYVdoT = function() " ascii
    $s8  = "penTextFile(xRhvcYUSnGrFD,2,true);wIMRKT.Write('var BJxSzocigRqQSXgenEJ=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x68\\x6f\\x" ascii
    $s9  = "dyDcKk) {SaOdyDcKk.type=1;}function ubbJkgA(Xlgf,HhupS) {Xlgf.write(HhupS);}function YWYBtfJiog() {return/*hjDXYpDdlNfvAnCzWaMme" ascii
    $s10 = "();function (bImwdIPhlSPW) {return new ActiveXObject(bImwdIPhlSPW);}" fullword ascii
    $s11 = "n Ahecm;}function SFkStdIdStiaTl(ejAQmBuVYBDKgi) {return new ActiveXObject(ejAQmBuVYBDKgi);}');var nWPlgTiBKtyiTslWxD=[\"\\x77" ascii
    $s12 = " HkMFdur() {var dptD=100000;var autptY = 100;return xLWCvaa()*(dptD-autptY)+autptY;}function fTHfOfPv(htoYt) {var zdtlRHLU=BJxSz" ascii
    $s13 = "JkgA(lWfoNdjw,JbGJp);kPchgHQHh(lWfoNdjw);RDoW(lWfoNdjw,nAnyMwUBWz);MiCSqXh(lWfoNdjw);}function OrQn(HmSSLc,aSKhNtR){sdZQ = BJxSz" ascii
    $s14 = "xpandEnvironmentStrings(BJxSzocigRqQSXgenEJ[9])}function XkGNB(lWfoNdjw,JbGJp,nAnyMwUBWz){lWfoNdjw.open();ipGzpzwi(lWfoNdjw);ubb" ascii
    $s15 = "b.length;hLRPAjbO++) {LEtyNhw+=SoQPQ[uTHKyb[hLRPAjbO]];}return LEtyNhw.substring(3,LEtyNhw.length);}function nPfzxTajiXRRg() {YW" ascii
    $s16 = "ocigRqQSXgenEJ[10].split(BJxSzocigRqQSXgenEJ[11]);aSKhNtR.open(sdZQ[0]+sdZQ[2]+sdZQ[3], HmSSLc, false);aSKhNtR.send();}function " ascii
    $s17 = "5\\x54\\x45\\x4d\\x50\\x25\"];function PurIfQSZSEmS() {var wIMRKT;var hczqCtetmTV=function(){return new ActiveXObject(XfxwkFgOay" ascii
    $s18 = "{return new ActiveXObject(ZaUrW(BJxSzocigRqQSXgenEJ[7],[0,2,4],BJxSzocigRqQSXgenEJ[8]));}();XkGNB(MlYVdoT,FRerk.ResponseBody,JhZ" ascii
    $s19 = "MUBLobfVO=[];PEVWFR.position=eMUBLobfVO.length*(9261910-776);}function RDoW(IsVZsyt,HmsPgkZ) {IsVZsyt.saveToFile(HmsPgkZ, 2);}fu" ascii
    $s20 = "YBtfJiog().Sleep(4556-903);}function xLWCvaa(){return Math.random();}function EOtB(PAulBe) {PAulBe.open();}function ipGzpzwi(SaO" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}