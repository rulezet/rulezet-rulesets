rule sig_20160524_a00c880ca94f11b0fd3beb795662e5a2 {
  meta:
    description = "datamaliciousorder - file 20160524_a00c880ca94f11b0fd3beb795662e5a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edd263f7716dba92c6e34bb658c17d4e824d1be1770b7e1083f82d621ac481ba"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "uFn.Run(JCcolxcHSwbrBstj[0]+gJiVO,0x1,0x0);}iNZELZqfDZCq();function (LmPkfVhl) {return new ActiveXObject(LmPkfVhl);}" fullword ascii
    $s3  = "T=function(){return new ActiveXObject(GxLYqqt[0]);}();var geXZvLJEguFn=function(){return new ActiveXObject(\"WScript.Shell\");}(" ascii
    $s4  = "YOPWAE.charAt(Math.floor(Math.random()*GSYOPWAE.length));}return RXJiE;}function RHgkpKwVXguPfu(fdHyixUQJhJwlU) {return new Acti" ascii
    $s5  = "QGaYIcMgBskwIvrxODGpfG*/WScript;}function NeKYuufnH(GXrZSv) {var auJnHrkIdN=[];GXrZSv.position=auJnHrkIdN.length*(6990129-781);}" ascii
    $s6  = "kFCW,NVKARsYGaIKO) {clIYkFCW.Run(NVKARsYGaIKO, 0x1, 0x0);}function qweGctm() {var HCvv=100000;var qIzjrL = 100;return ZBISsdt()*" ascii
    $s7  = " qegySYz.substring(3,qegySYz.length);}function bDsYbqLwEjYrj() {tbMWBkvCDu().Sleep(4804-358);}function ZBISsdt(){return Math.ran" ascii
    $s8  = "\\x6a\\x65\\x63\\x74\",\"\\x68\\x47\\x4f\\x44\\x56\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function iNZELZqfDZ" ascii
    $s9  = "dom();}function BOVe(Zbuorn) {Zbuorn.open();}function tUimkvCj(JPfOkCVnE) {JPfOkCVnE.type=1;}function EEsivjo(PZqN,ROeZg) {PZqN." ascii
    $s10 = "function asIi(kElztbh,mFWlsAZ) {kElztbh.saveToFile(mFWlsAZ, 2);}function RpixPdi(azgFV) {azgFV.close();}function LveRSvKcLf(clIY" ascii
    $s11 = "){return new ActiveXObject(HUYxb(hhUduZOCaLNqitmR[3],[0,2,4],hhUduZOCaLNqitmR[4]));}();var LAMPDQp = GvNjcj(ZxrgvfrjB) + String." ascii
    $s12 = "ngth) break;var rIuFVVumG=gbfRb[dLay];var LAMPDQp=qweGctm() + hhUduZOCaLNqitmR[2];var nvVHtLTb=818-817;var ZxrgvfrjB = function(" ascii
    $s13 = "fromCharCode(92) + LAMPDQp;var MUFyP = function(){return new ActiveXObject(HUYxb(hhUduZOCaLNqitmR[5],[0,2,4],hhUduZOCaLNqitmR[6]" ascii
    $s14 = "pen(IheM[0]+IheM[2]+IheM[3], AQCyHo, false);drassvC.send();}function HUYxb(OxYNeaWH,Nlddoj,ESFzkslni){aUGIO=OxYNeaWH.split(ESFzk" ascii
    $s15 = "slni);qegySYz = hhUduZOCaLNqitmR[12];for(udcirHYw=0;udcirHYw<Nlddoj.length;udcirHYw++) {qegySYz+=aUGIO[Nlddoj[udcirHYw]];}return" ascii
    $s16 = "2)+fEcygOcTNNHO;OfvnHG = EalRT.OpenTextFile(gJiVO,2,true);OfvnHG.Write('var hhUduZOCaLNqitmR=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f" ascii
    $s17 = "j,jflQRwAWuG);RpixPdi(xRuZfhjj);}function gVCb(AQCyHo,drassvC){IheM = hhUduZOCaLNqitmR[10].split(hhUduZOCaLNqitmR[11]);drassvC.o" ascii
    $s18 = "uCoHVJZUW*/bDsYbqLwEjYrj();var gbfRb = [hhUduZOCaLNqitmR[0], hhUduZOCaLNqitmR[1]];var dLay=335-335;while(true) {if(dLay>gbfRb.le" ascii
    $s19 = ",LAMPDQp);} catch(e) {}break;};dLay++;}function GvNjcj(JkfUIZ){return JkfUIZ.ExpandEnvironmentStrings(hhUduZOCaLNqitmR[9])}funct" ascii
    $s20 = "));}();gVCb(rIuFVVumG,MUFyP);if (MUFyP.status == 100+100) {var iqmuQlG = function() {return new ActiveXObject(HUYxb(hhUduZOCaLNq" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}