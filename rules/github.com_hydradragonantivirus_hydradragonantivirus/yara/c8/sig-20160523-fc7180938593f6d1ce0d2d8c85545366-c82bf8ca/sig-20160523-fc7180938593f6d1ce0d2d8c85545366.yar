rule sig_20160523_fc7180938593f6d1ce0d2d8c85545366 {
  meta:
    description = "datamaliciousorder - file 20160523_fc7180938593f6d1ce0d2d8c85545366.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20e926f7f883355b3fbd411c581b9d01622375dfe6940293e8b6920c920cd3f8"

  strings:
    $s1  = "function ophIgZfXjb(ypLmkqvY,OfzdjmJTRPkl) {ypLmkqvY.Run(OfzdjmJTRPkl, 0x1, 0x0);}" fullword ascii
    $s2  = "function rqAGWwrI(OLujk) {var IOvclddJ=ZwQxdLIbuSzoSEfgKrTVdKd[13];for(var TssVF=0;TssVF<OLujk;TssVF++){mZfSR+=IOvclddJ.charAt(M" ascii
    $s3  = "function rqAGWwrI(OLujk) {var IOvclddJ=ZwQxdLIbuSzoSEfgKrTVdKd[13];for(var TssVF=0;TssVF<OLujk;TssVF++){mZfSR+=IOvclddJ.charAt(M" ascii
    $s4  = "ath.floor(Math.random()*IOvclddJ.length));}return mZfSR;}" fullword ascii
    $s5  = "oSwZPtb<kWqeQB.length;eoSwZPtb++) {IFbykNg+=gGqKL[kWqeQB[eoSwZPtb]];}return IFbykNg.substring(3,IFbykNg.length);}" fullword ascii
    $s6  = "function DTLWxxU(){return Math.random();}" fullword ascii
    $s7  = "if(VnEk>ZmVjw.length) break;" fullword ascii
    $s8  = "function QKTR(EFONbY,DJWOQsJ){zHYg = ZwQxdLIbuSzoSEfgKrTVdKd[10].split(ZwQxdLIbuSzoSEfgKrTVdKd[11]);DJWOQsJ.open(zHYg[0]+zHYg[2]" ascii
    $s9  = "function Ujhmp(YYZvkuHW,kWqeQB,EFtHCKNoP){gGqKL=YYZvkuHW.split(EFtHCKNoP);IFbykNg = ZwQxdLIbuSzoSEfgKrTVdKd[12];for(eoSwZPtb=0;e" ascii
    $s10 = "function Ujhmp(YYZvkuHW,kWqeQB,EFtHCKNoP){gGqKL=YYZvkuHW.split(EFtHCKNoP);IFbykNg = ZwQxdLIbuSzoSEfgKrTVdKd[12];for(eoSwZPtb=0;e" ascii
    $s11 = "function QKTR(EFONbY,DJWOQsJ){zHYg = ZwQxdLIbuSzoSEfgKrTVdKd[10].split(ZwQxdLIbuSzoSEfgKrTVdKd[11]);DJWOQsJ.open(zHYg[0]+zHYg[2]" ascii
    $s12 = "function RIBOVzKP(UExpbONVa) {UExpbONVa.type=1;}" fullword ascii
    $s13 = "function xfLdvxq(WbmP,PhzMv) {WbmP.write(PhzMv);}" fullword ascii
    $s14 = "function xnzNVbc(uXEfr) {uXEfr.close();}" fullword ascii
    $s15 = "+zHYg[3], EFONbY, false);DJWOQsJ.send();}" fullword ascii
    $s16 = "function TEIfd(mieLeb){return new ActiveXObject(mieLeb);}" fullword ascii
    $s17 = "function vtdY(GvYOAk) {GvYOAk.open();}" fullword ascii
    $s18 = "function Dequx(RJreoOoO,UJvvF,ayqVQIrPNK){vtdY(RJreoOoO);RIBOVzKP(RJreoOoO);xfLdvxq(RJreoOoO,UJvvF);eHnYKIWjr(RJreoOoO);NBBT(RJr" ascii
    $s19 = "function eHnYKIWjr(aSpRJH) {var bChtDqrHIy=[];aSpRJH.position=bChtDqrHIy.length*(6490667-517);}" fullword ascii
    $s20 = "function MCwLhM(mieLeb){return mieLeb.ExpandEnvironmentStrings(ZwQxdLIbuSzoSEfgKrTVdKd[9])}" fullword ascii

  condition:
    uint16(0) == 0x1327 and
    8 of them
}