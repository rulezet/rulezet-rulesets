rule sig_20160524_2bc55bb5e16b80bc09d6eff0ff936019 {
  meta:
    description = "datamaliciousorder - file 20160524_2bc55bb5e16b80bc09d6eff0ff936019.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "575c6b36886e44eaf7c96c222dd4836474eca55aa9b79e2abc2d834845c3b232"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "return new ActiveXObject(\"WScript.Shell\");}();var JjlveehUd = ypUrbRKcIVjEyRJbQTkDowo[1]+11181+ypUrbRKcIVjEyRJbQTkDowo[2];var " ascii
    $s3  = "jtSSvfMzFsrKFeklNPynUxJAs*/WScript;}function HtQRgDJbB(rzUPnX) {var OvxqCrypAb=[];rzUPnX.position=OvxqCrypAb.length*(8323668-836" ascii
    $s4  = "();xiFdCDh.Run(KShJeTAgwLIIURFM[0]+ThpQoGZcp,0x1,0x0);}kUgyEQlmauZ();function (RHurpDxGKbWLpH) {return new ActiveXObject(RHurpDx" ascii
    $s5  = "gJMOxYs,tlwrIjvjJANQ) {mgJMOxYs.Run(tlwrIjvjJANQ, 0x1, 0x0);}function mZQATdA() {var zjbt=100000;var iArAKJ = 100;return mIhKHQs" ascii
    $s6  = "s+=VJzslxiC.charAt(Math.floor(Math.random()*VJzslxiC.length));}return RgoWs;}function yypuJHMPyyzVKU(hwKwQEqbefThck) {return new" ascii
    $s7  = "mLDOtg=hxQJx[KhNY];var eMUVvcB=mZQATdA() + DqeZxNaqfaGsjWErVz[2];var vbQyxTFy=659-658;var uxBMeLjZS = function(){return new Acti" ascii
    $s8  = "92) + eMUVvcB;var pEyvI = function(){return new ActiveXObject(jhWNv(DqeZxNaqfaGsjWErVz[5],[0,2,4],DqeZxNaqfaGsjWErVz[6]));}();qv" ascii
    $s9  = "Ic(QUDmLDOtg,pEyvI);if (pEyvI.status == 100+100) {var gjefYVD = function() {return new ActiveXObject(jhWNv(DqeZxNaqfaGsjWErVz[7]" ascii
    $s10 = ");}function xeAz(YwWhfCE,ZzgQAiv) {YwWhfCE.saveToFile(ZzgQAiv, 2);}function yGNgVSt(yYhEj) {yYhEj.close();}function YXyyOnIcMB(m" ascii
    $s11 = "o();var hxQJx = [DqeZxNaqfaGsjWErVz[0], DqeZxNaqfaGsjWErVz[1]];var KhNY=552-552;while(true) {if(KhNY>hxQJx.length) break;var QUD" ascii
    $s12 = "TX.OpenTextFile(ThpQoGZcp,2,true);hfaxpEaLuQuiV.Write('var DqeZxNaqfaGsjWErVz=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61\\x75" ascii
    $s13 = "()*(zjbt-iArAKJ)+iArAKJ;}function WyTequSC(yRtuQ) {var VJzslxiC=DqeZxNaqfaGsjWErVz[13];for(var SWnsu=0;SWnsu<yRtuQ;SWnsu++){RgoW" ascii
    $s14 = "x65\\x6d\\x4f\\x62\\x6a\\x65\\x63\\x74\",\"\\x6a\\x79\\x73\\x56\\x75\\x59\\x6f\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50" ascii
    $s15 = "urn bSuEkOm.substring(3,bSuEkOm.length);}function AZlaWXfjkItLo() {dXQMTLwUMB().Sleep(4893-669);}function mIhKHQs(){return Math." ascii
    $s16 = "PE.write(GEHKz);}function dXQMTLwUMB() {return/*WOLFjswIAeYVNWVeptsvWtVEcuIRxwjTzVFXcSzMvJWyyuCUCwvkzPhfHWQRRQagwWRiolUJKioVCLDD" ascii
    $s17 = "MONWGMrlO);yGNgVSt(ilOlHiVm);}function qvIc(wEYNEX,rPMfAys){hKHv = DqeZxNaqfaGsjWErVz[10].split(DqeZxNaqfaGsjWErVz[11]);rPMfAys." ascii
    $s18 = "random();}function uhJR(BYfDKR) {BYfDKR.open();}function vaZYyhbf(GwTvJRgIb) {GwTvJRgIb.type=1;}function RUczuMo(vZPE,GEHKz) {vZ" ascii
    $s19 = "open(hKHv[0]+hKHv[2]+hKHv[3], wEYNEX, false);rPMfAys.send();}function jhWNv(ttVTOdDW,SdVvCY,KHqUfAivT){Mnaaz=ttVTOdDW.split(KHqU" ascii
    $s20 = ") {var hfaxpEaLuQuiV;var cCDqMOSxLTX=function(){return new ActiveXObject(ypUrbRKcIVjEyRJbQTkDowo[0]);}();var xiFdCDh=function(){" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}