rule sig_20160524_fa997672bd666f9c3c2683fd45860f4b {
  meta:
    description = "datamaliciousorder - file 20160524_fa997672bd666f9c3c2683fd45860f4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2679b8303f0a81915f88064816c450699ac5fb8e1735e784375225dc72b9e2"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "ar XkpVADnyGJLmF;var DdlLVMhPBLcHSa=function(){return new ActiveXObject(BXTUuIgMYVQp[0]);}();var xWobJewewAEUy=function(){return" ascii
    $s3  = "crnZ[1]];var PtQB=359-359;while(true) {if(PtQB>pCnWt.length) break;var BJHHxIfOU=pCnWt[PtQB];var kXgZzcI=QRBnxBR() + aBKmQKdCUHT" ascii
    $s4  = "QKdCUHTFSKuBcrnZ[4]));}();var kXgZzcI = LkzPCP(xHJEZjjCh) + String.fromCharCode(92) + kXgZzcI;var aFEIV = function(){return new " ascii
    $s5  = "ath.random()*QDAMKQpi.length));}return teYag;}function DOtMuYuFqaTAwh(IvrdeOgZaEtINp) {return new ActiveXObject(IvrdeOgZaEtINp);" ascii
    $s6  = "ecusepyKSnvla,2,true);XkpVADnyGJLmF.Write('var aBKmQKdCUHTFSKuBcrnZ=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x64\\x61\\x76\\x69" ascii
    $s7  = "length);}function VkmTHugdWamVY() {hqCWtQmmcX().Sleep(4421-756);}function xZDYJxM(){return Math.random();}function xfgt(zigMYS) " ascii
    $s8  = "hN, false);smcSygg.send();}function QMjdu(crGyzFNH,OrVais,cirbJkAkL){bREKB=crGyzFNH.split(cirbJkAkL);nhjTpWx = aBKmQKdCUHTFSKuBc" ascii
    $s9  = "MwmsutIc[0]+secusepyKSnvla,0x1,0x0);}sifcwEAmFBz();function (iFtvpOYrYz) {return new ActiveXObject(iFtvpOYrYz);}" fullword ascii
    $s10 = "rnZ[12];for(KwkJOpUB=0;KwkJOpUB<OrVais.length;KwkJOpUB++) {nhjTpWx+=bREKB[OrVais[KwkJOpUB]];}return nhjTpWx.substring(3,nhjTpWx." ascii
    $s11 = "un(drAUePbmzxjs, 0x1, 0x0);}function QRBnxBR() {var wBCK=100000;var SGFxZT = 100;return xZDYJxM()*(wBCK-SGFxZT)+SGFxZT;}function" ascii
    $s12 = "x6a\\x65\\x63\\x74\",\"\\x6c\\x4b\\x77\\x64\\x71\\x54\\x4f\\x62\\x65\\x61\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25" ascii
    $s13 = " {nhjyEhX.saveToFile(ScLQeYp, 2);}function SvjUKAc(XwHvx) {XwHvx.close();}function GzERupxfqO(sLAgfHCf,drAUePbmzxjs) {sLAgfHCf.R" ascii
    $s14 = "FSKuBcrnZ[2];var pnLSVMQJ=495-494;var xHJEZjjCh = function(){return new ActiveXObject(QMjdu(aBKmQKdCUHTFSKuBcrnZ[3],[0,2,4],aBKm" ascii
    $s15 = "pt;}function clxNxtIxX(mhEOIT) {var NIZqdPcxeV=[];mhEOIT.position=NIZqdPcxeV.length*(463736-577);}function jMWm(nhjyEhX,ScLQeYp)" ascii
    $s16 = "on LkzPCP(UQICuk){return UQICuk.ExpandEnvironmentStrings(aBKmQKdCUHTFSKuBcrnZ[9])}function fMTKQ(FAbmUNmd,XfyCG,AptnxROKUH){FAbm" ascii
    $s17 = "100) {var eetkGco = function() {return new ActiveXObject(QMjdu(aBKmQKdCUHTFSKuBcrnZ[7],[0,2,4],aBKmQKdCUHTFSKuBcrnZ[8]));}();fMT" ascii
    $s18 = "UNmd.open();cAlHXVdz(FAbmUNmd);IpDdQcr(FAbmUNmd,XfyCG);clxNxtIxX(FAbmUNmd);jMWm(FAbmUNmd,AptnxROKUH);SvjUKAc(FAbmUNmd);}function" ascii
    $s19 = "KQ(eetkGco,aFEIV.ResponseBody,kXgZzcI);}if (pnLSVMQJ > 0){try {GzERupxfqO(xHJEZjjCh,kXgZzcI);} catch(e) {}break;};PtQB++;}functi" ascii
    $s20 = "{zigMYS.open();}function cAlHXVdz(yJUSJbBLj) {yJUSJbBLj.type=1;}function IpDdQcr(VkhA,Rcvdw) {VkhA.write(Rcvdw);}function hqCWtQ" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}