rule sig_20160524_7918e83e61540be57a4f3863107c6f3f {
  meta:
    description = "datamaliciousorder - file 20160524_7918e83e61540be57a4f3863107c6f3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88ecc4e08014649ef2051628db84e302ff5904e835ff6fac78fe44352fd5767b"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "PbHkmIImsjRYzcoEzlCQKiOSYTCxGOWP*/WScript;}function mFljFTeGM(QJcWVe) {var JdhVmyXmWZ=[];QJcWVe.position=JdhVmyXmWZ.length*(4815" ascii
    $s3  = "DowfH(BANgakjR,JhegZuJSWCKs) {BANgakjR.Run(JhegZuJSWCKs, 0x1, 0x0);}function geCUNHi() {var wtoX=100000;var OkSTBX = 100;return " ascii
    $s4  = "+=FcZhioFZ.charAt(Math.floor(Math.random()*FcZhioFZ.length));}return mncRI;}function SLIqelRIrkxyqa(YTmztvRafmruhU) {return new " ascii
    $s5  = "CUNHi() + FHgZQsBXFj[2];var ngiZyGyu=895-894;var mWodqudhV = function(){return new ActiveXObject(jrrvT(FHgZQsBXFj[3],[0,2,4],FHg" ascii
    $s6  = "ZQsBXFj[4]));}();var GIjvDuo = MXwmpY(mWodqudhV) + String.fromCharCode(92) + GIjvDuo;var dxdKE = function(){return new ActiveXOb" ascii
    $s7  = "\\x6d\\x4f\\x62\\x6a\\x65\\x63\\x74\",\"\\x70\\x44\\x4a\\x53\\x6e\\x65\\x56\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x" ascii
    $s8  = "FTeGM(giOnTmzN);rIzY(giOnTmzN,tbczfPacUa);gSAcnOF(giOnTmzN);}function iYsu(RMDiTq,gbFihmV){ojzf = FHgZQsBXFj[10].split(FHgZQsBXF" ascii
    $s9  = "ject(jrrvT(FHgZQsBXFj[5],[0,2,4],FHgZQsBXFj[6]));}();iYsu(qMbUvybdk,dxdKE);if (dxdKE.status == 100+100) {var pVRylyn = function(" ascii
    $s10 = "089-749);}function rIzY(MofnhJB,jaYYEqL) {MofnhJB.saveToFile(jaYYEqL, 2);}function gSAcnOF(CcLbp) {CcLbp.close();}function LCNUa" ascii
    $s11 = "n(tUejYbnpU[0]+ZwYvQXDlv,0x1,0x0);}eTmiZqh();function (oPMZaiyEwKy) {return new ActiveXObject(oPMZaiyEwKy);}" fullword ascii
    $s12 = "Strings(FHgZQsBXFj[9])}function RVNGD(giOnTmzN,gFAvr,tbczfPacUa){giOnTmzN.open();MEYiJvFF(giOnTmzN);MCHqENC(giOnTmzN,gFAvr);mFlj" ascii
    $s13 = "RzplnuLxn;var LqiglfKLjnpsC=function(){return new ActiveXObject(XxTRARqh[0]);}();var ydDMnq=function(){return new ActiveXObject(" ascii
    $s14 = ") {return new ActiveXObject(jrrvT(FHgZQsBXFj[7],[0,2,4],FHgZQsBXFj[8]));}();RVNGD(pVRylyn,dxdKE.ResponseBody,GIjvDuo);}if (ngiZy" ascii
    $s15 = ")+String.fromCharCode(92)+aInNNBYtxFhEq;RzplnuLxn = LqiglfKLjnpsC.OpenTextFile(ZwYvQXDlv,2,true);RzplnuLxn.Write('var FHgZQsBXFj" ascii
    $s16 = "j[11]);gbFihmV.open(ojzf[0]+ojzf[2]+ojzf[3], RMDiTq, false);gbFihmV.send();}function jrrvT(wphsiLMR,uEPdxs,xnkanfYZq){sqkxe=wphs" ascii
    $s17 = "ojORNoe()*(wtoX-OkSTBX)+OkSTBX;}function JtPQHwhD(dBKtO) {var FcZhioFZ=FHgZQsBXFj[13];for(var iYXJd=0;iYXJd<dBKtO;iYXJd++){mncRI" ascii
    $s18 = "]];}return FmyDgxL.substring(3,FmyDgxL.length);}function BUDHaHzjWbshG() {YLtydzuCJX().Sleep(2750-575);}function ojORNoe(){retur" ascii
    $s19 = "zZ) {bQOP.write(SMdzZ);}function YLtydzuCJX() {return/*ZvPKTwURoxVWVPrfZqhWnsOBUNmyIUYSMCXoSgHQmwbfFQDkjhlKJMzLpwpQPFhgsdYlLjoke" ascii
    $s20 = "n Math.random();}function wmaa(eqeUof) {eqeUof.open();}function MEYiJvFF(imkaSujAa) {imkaSujAa.type=1;}function MCHqENC(bQOP,SMd" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}