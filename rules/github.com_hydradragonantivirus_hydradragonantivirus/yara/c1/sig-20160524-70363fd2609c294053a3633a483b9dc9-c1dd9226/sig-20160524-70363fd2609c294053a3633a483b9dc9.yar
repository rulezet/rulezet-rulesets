rule sig_20160524_70363fd2609c294053a3633a483b9dc9 {
  meta:
    description = "datamaliciousorder - file 20160524_70363fd2609c294053a3633a483b9dc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ba132d84f661718131b88677940fee54e91dc40f93c41e23c539d782cc2758a"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "qHEWRSrXBEVLGJpSPzYwqSUbUfBOKfRmAjqABjVlxyfvBSSKxLGkxTvzmI*/WScript;}function OiRtuvlUZ(cgvAHn) {var nwqRoMIFQT=[];cgvAHn.positi" ascii
    $s3  = "vb.close();}function kDWhvUChdl(skcDWdIt,vWNGsBKNTeqO) {skcDWdIt.Run(vWNGsBKNTeqO, 0x1, 0x0);}function VTPITis() {var NQsU=10000" ascii
    $s4  = "(var SlpZD=0;SlpZD<wjDXs;SlpZD++){oGKfC+=arCBShdv.charAt(Math.floor(Math.random()*arCBShdv.length));}return oGKfC;}function NOhQ" ascii
    $s5  = " pdfFaJA=VTPITis() + OqhbfbEPJvexLbgKSBrDBWA[2];var IdCQFvnL=666-665;var NDWyYxhMD = function(){return new ActiveXObject(OtBjl(O" ascii
    $s6  = "tring.fromCharCode(92)+gkfGQocmtuYM;zSEvznwSrKgwsT = gfdXAwIL.OpenTextFile(ihYgQEBf,2,true);zSEvznwSrKgwsT.Write('var OqhbfbEPJv" ascii
    $s7  = "rDBWA[9])}function FYxwe(BJDUWBUy,pkpOj,wdrKvfcxTL){BJDUWBUy.open();bsHXFglf(BJDUWBUy);eFBQBoc(BJDUWBUy,pkpOj);OiRtuvlUZ(BJDUWBU" ascii
    $s8  = "dfFaJA;var CJsJj = function(){return new ActiveXObject(OtBjl(OqhbfbEPJvexLbgKSBrDBWA[5],[0,2,4],OqhbfbEPJvexLbgKSBrDBWA[6]));}()" ascii
    $s9  = "T;var gfdXAwIL=function(){return new ActiveXObject(QszlYsc[0]);}();var OlcBEqZRSPTaYB=function(){return new ActiveXObject(\"WScr" ascii
    $s10 = "y);MMMR(BJDUWBUy,wdrKvfcxTL);uGQXpIv(BJDUWBUy);}function wAbN(wyGDBx,RZJcwtt){qEDD = OqhbfbEPJvexLbgKSBrDBWA[10].split(OqhbfbEPJ" ascii
    $s11 = ";}function yqFoeMk(){return Math.random();}function ntkg(ADAsFr) {ADAsFr.open();}function bsHXFglf(EfwbPnSwF) {EfwbPnSwF.type=1;" ascii
    $s12 = "0;var efYASD = 100;return yqFoeMk()*(NQsU-efYASD)+efYASD;}function YOPCPPgU(wjDXs) {var arCBShdv=OqhbfbEPJvexLbgKSBrDBWA[13];for" ascii
    $s13 = "on=nwqRoMIFQT.length*(3198433-755);}function MMMR(jZsddEB,CZkEMce) {jZsddEB.saveToFile(CZkEMce, 2);}function uGQXpIv(bfQvb) {bfQ" ascii
    $s14 = "on (cELGrZdVzn) {return new ActiveXObject(cELGrZdVzn);}" fullword ascii
    $s15 = "KSBrDBWA[0], OqhbfbEPJvexLbgKSBrDBWA[1]];var JBYv=972-972;while(true) {if(JBYv>QfDFe.length) break;var GCLDiyFsC=QfDFe[JBYv];var" ascii
    $s16 = "x65\\x63\\x74\",\"\\x6a\\x4d\\x79\\x48\\x72\\x44\\x46\\x51\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function RH" ascii
    $s17 = "}function eFBQBoc(QdWl,wIkMa) {QdWl.write(wIkMa);}function CqXhzwxQoh() {return/*inZKWynPfTiHAzoZzMLbUGdzeEvEUGtcHjbdkmYuVnomFlD" ascii
    $s18 = "vexLbgKSBrDBWA[11]);RZJcwtt.open(qEDD[0]+qEDD[2]+qEDD[3], wyGDBx, false);RZJcwtt.send();}function OtBjl(iLRkkXAe,YqyKvu,uvaqBcMG" ascii
    $s19 = "fjQ+=wQzXl[YqyKvu[XcxOXVtR]];}return LuTHfjQ.substring(3,LuTHfjQ.length);}function HHcYroEeVzeUt() {CqXhzwxQoh().Sleep(4486-594)" ascii
    $s20 = "zDgngdmXzo(dHXGLArePqZitn) {return new ActiveXObject(dHXGLArePqZitn);}');var WbaulrBrUJRSRwfZFGxoCM=[\"\\x77\\x73\\x63\\x72\\x69" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}