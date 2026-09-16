rule sig_20160523_c2b00dd13a5401d739a2379f60e80505 {
  meta:
    description = "datamaliciousorder - file 20160523_c2b00dd13a5401d739a2379f60e80505.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "484e6da9b08959afd6216b24325538b1f12b6fab5a1c6e55c9ffe1dd9b34e2cd"

  strings:
    $s1  = "function nnRbGOcNHy(OrvCTMCM,JvfnbqLQpXxH) {OrvCTMCM.Run(JvfnbqLQpXxH, 0x1, 0x0);}" fullword ascii
    $s2  = "function LEoLmale(ySOtg) {var zxIvLiDc=ZUNAbOAxAhmYVWf[2];for(var VvhoV=0;VvhoV<ySOtg;VvhoV++){ibOdT+=zxIvLiDc.charAt(Math.floor" ascii
    $s3  = "function LEoLmale(ySOtg) {var zxIvLiDc=ZUNAbOAxAhmYVWf[2];for(var VvhoV=0;VvhoV<ySOtg;VvhoV++){ibOdT+=zxIvLiDc.charAt(Math.floor" ascii
    $s4  = "function vUSer(ExZyliqB,gzhLh,sdNGnjUvie){EdAU(ExZyliqB);fXuaGeFq(ExZyliqB);ZSQfTXc(ExZyliqB,gzhLh);nhEjtHnXe(ExZyliqB);JjuY(ExZ" ascii
    $s5  = "function vUSer(ExZyliqB,gzhLh,sdNGnjUvie){EdAU(ExZyliqB);fXuaGeFq(ExZyliqB);ZSQfTXc(ExZyliqB,gzhLh);nhEjtHnXe(ExZyliqB);JjuY(ExZ" ascii
    $s6  = "function mNPSXIX() {var ZGuh=100000;var TQJNZI = 100;return ZJhOjMb()*(ZGuh-TQJNZI)+TQJNZI;}" fullword ascii
    $s7  = "function ZSQfTXc(cyUk,DbAlm) {cyUk.write(DbAlm);}" fullword ascii
    $s8  = "function QRBT(MNrgvA,cXbWGXq){tCkz = ZUNAbOAxAhmYVWf[11].split(ZUNAbOAxAhmYVWf[12]);cXbWGXq.open(tCkz[0]+tCkz[2]+tCkz[3], MNrgvA" ascii
    $s9  = "try{IznyWbr=AeJDPPqZN(xsxSz[vhdL], mNPSXIX() + ZUNAbOAxAhmYVWf[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function AeJDPPqZN(CqnKcbdpE,ONGoOjG,IOKPUYhe){" fullword ascii
    $s11 = "function ZJhOjMb(){return Math.random();}" fullword ascii
    $s12 = "function EdAU(zffYpn) {zffYpn.open();}" fullword ascii
    $s13 = "function vOUEc(FnpxQY){return new ActiveXObject(FnpxQY);}" fullword ascii
    $s14 = "function nhEjtHnXe(sKJHgU) {var XLoqSEJVYW=[];sKJHgU.position=XLoqSEJVYW.length*(5208820-103);}" fullword ascii
    $s15 = "function PkgvFv(FnpxQY){return FnpxQY.ExpandEnvironmentStrings(ZUNAbOAxAhmYVWf[10])}" fullword ascii
    $s16 = "(Math.random()*zxIvLiDc.length));}return ibOdT;}" fullword ascii
    $s17 = "if (IznyWbr==0) break;" fullword ascii
    $s18 = "function QRBT(MNrgvA,cXbWGXq){tCkz = ZUNAbOAxAhmYVWf[11].split(ZUNAbOAxAhmYVWf[12]);cXbWGXq.open(tCkz[0]+tCkz[2]+tCkz[3], MNrgvA" ascii
    $s19 = "function LauJHrf(KYjPI) {KYjPI.close();}" fullword ascii
    $s20 = "function JjuY(ecNwobf,BdcdYRG) {ecNwobf.saveToFile(BdcdYRG, 2);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}