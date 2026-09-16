rule sig_20160524_163a39fbc6638c29d22bbb1ec04d3648 {
  meta:
    description = "datamaliciousorder - file 20160524_163a39fbc6638c29d22bbb1ec04d3648.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75263591a5fc76b23493d5941a522c2d985b279aebca0859693533734ee30acc"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "return new ActiveXObject(YNBUCXGvSmo[0]);}();var uqLCE=function(){return new ActiveXObject(\"WScript.Shell\");}();var FGatsGhZlI" ascii
    $s3  = "jHYLYiZOEMNrMLLCHWUZcLLMiXhuJXJdRDorsgupxAbCRb*/WScript;}function cNrBAYqNx(eqzQHc) {var cePLpledDL=[];eqzQHc.position=cePLpledD" ascii
    $s4  = "o.Close();uqLCE.Run(NtYWJ[0]+LPBoMZVYJ,0x1,0x0);}vFaEaN();function (JnlNtsVwWG) {return new ActiveXObject(JnlNtsVwWG);}" fullword ascii
    $s5  = "function JiEyfqicza(wkJjaIar,XGrvSQZVRyRO) {wkJjaIar.Run(XGrvSQZVRyRO, 0x1, 0x0);}function cZsNLFu() {var XUIU=100000;var TUGYMD" ascii
    $s6  = "NadqkdZ);HqJA(WNadqkdZ,OjbYSwFJVN);lJDzRdG(WNadqkdZ);}function rlia(jirCGF,IjGiRpH){VeKJ = cQxMvybmUbaUmLEgj[10].split(cQxMvybmU" ascii
    $s7  = "<gdMFt;Gigbq++){Qjfqi+=sEwujaIG.charAt(Math.floor(Math.random()*sEwujaIG.length));}return Qjfqi;}function wPyduwwfMoaUqq(QizaXhf" ascii
    $s8  = "baUmLEgj[11]);IjGiRpH.open(VeKJ[0]+VeKJ[2]+VeKJ[3], jirCGF, false);IjGiRpH.send();}function McusU(jdeedntJ,jevByh,WXvBiPYQQ){SFE" ascii
    $s9  = "sQXeI) + String.fromCharCode(92) + xbzfaFz;var IWetV = function(){return new ActiveXObject(McusU(cQxMvybmUbaUmLEgj[5],[0,2,4],cQ" ascii
    $s10 = "ifGL>laRkE.length) break;var ZAnnMofHR=laRkE[ifGL];var xbzfaFz=cZsNLFu() + cQxMvybmUbaUmLEgj[2];var VuXUdFHu=283-282;var WeOlsQX" ascii
    $s11 = "eI = function(){return new ActiveXObject(McusU(cQxMvybmUbaUmLEgj[3],[0,2,4],cQxMvybmUbaUmLEgj[4]));}();var xbzfaFz = pZOztW(WeOl" ascii
    $s12 = "eXvllCFLaZYTRPEWBVdE*/FjMCgOTtdxyvs();var laRkE = [cQxMvybmUbaUmLEgj[0], cQxMvybmUbaUmLEgj[1]];var ifGL=878-878;while(true) {if(" ascii
    $s13 = "xMvybmUbaUmLEgj[6]));}();rlia(ZAnnMofHR,IWetV);if (IWetV.status == 100+100) {var oehpMHZ = function() {return new ActiveXObject(" ascii
    $s14 = "L.length*(5094252-240);}function HqJA(dibevRv,vpckXQb) {dibevRv.saveToFile(vpckXQb, 2);}function lJDzRdG(ITdFm) {ITdFm.close();}" ascii
    $s15 = "bmUbaUmLEgj[9])}function EVwIw(WNadqkdZ,gYJhZ,OjbYSwFJVN){WNadqkdZ.open();kUzKazbx(WNadqkdZ);ZrIenXO(WNadqkdZ,gYJhZ);cNrBAYqNx(W" ascii
    $s16 = " = 100;return NFNmynj()*(XUIU-TUGYMD)+TUGYMD;}function xlooGLKR(gdMFt) {var sEwujaIG=cQxMvybmUbaUmLEgj[13];for(var Gigbq=0;Gigbq" ascii
    $s17 = "FNmynj(){return Math.random();}function kswx(VGYBYa) {VGYBYa.open();}function kUzKazbx(KQKygQfyH) {KQKygQfyH.type=1;}function Zr" ascii
    $s18 = "77\\x51\\x74\\x6d\\x52\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function vFaEaN() {var nBydmMSWHAo;var uHElJGtG" ascii
    $s19 = "rZCyMbE) {return new ActiveXObject(QizaXhfrZCyMbE);}');var NtYWJ=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20" ascii
    $s20 = "evByh[wGffIsZM]];}return rxyacLA.substring(3,rxyacLA.length);}function FjMCgOTtdxyvs() {zpjyUzVZHQ().Sleep(3342-724);}function N" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}