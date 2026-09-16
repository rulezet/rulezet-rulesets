rule sig_20160527_eedadbddb0c1653cd972eb0e65d01653 {
  meta:
    description = "datamaliciousorder - file 20160527_eedadbddb0c1653cd972eb0e65d01653.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b62934ec5a486ae077c291b4ce4ab5a056b23e7e4901d875cb9c6050df828f37"

  strings:
    $s1  = "function SohOYeO(UdftpnMewEifn) {var ObLrBvUaFoOxxlXNjEytX = XFzoMgysPYzoL.join(dlAZmPgkFbU[6]);var cAYdlQ, ghIqNwxMUlSutgXrDwwJ" ascii
    $s2  = "function iHWmTmnIT() {return WScript;}function jnBaVuKlcYOjrn(){return UUdkAC.ExpandEnvironmentStrings(tlKpNfEUMlVTa())}" fullword ascii
    $s3  = "function SohOYeO(UdftpnMewEifn) {var ObLrBvUaFoOxxlXNjEytX = XFzoMgysPYzoL.join(dlAZmPgkFbU[6]);var cAYdlQ, ghIqNwxMUlSutgXrDwwJ" ascii
    $s4  = ", MITSYDYwgHlbONkyYnUt);} while (WMgxxfCWWobixv < UdftpnMewEifn.length);return dAIcZzc;}" fullword ascii
    $s5  = "function KsqQyKLMPvVOla(cCHxTkGFFKUMrzlzNAy,lvycOGWuzwjaoKIfJdII){return cCHxTkGFFKUMrzlzNAy.charAt(lvycOGWuzwjaoKIfJdII);}" fullword ascii
    $s6  = "length);}" fullword ascii
    $s7  = "function jUfoYnumCuAHnqCKgWPd(bPXZhBpyULhUOzSdsvQzFK,tcUhrOAa,SSdnpUbCHreIScOTRkXzVFc){return String.fromCharCode(bPXZhBpyULhUOz" ascii
    $s8  = "X=0;dOxYHhmklZEkNX<ggSrM.length;dOxYHhmklZEkNX++) {hNrqcVl+=GLumcOcJ[ggSrM[dOxYHhmklZEkNX]];}return hNrqcVl.substring(3,hNrqcVl." ascii
    $s9  = "function jUfoYnumCuAHnqCKgWPd(bPXZhBpyULhUOzSdsvQzFK,tcUhrOAa,SSdnpUbCHreIScOTRkXzVFc){return String.fromCharCode(bPXZhBpyULhUOz" ascii
    $s10 = "function tlKpNfEUMlVTa(){return LAwQYz(dlAZmPgkFbU[8],[1,5,7],dlAZmPgkFbU[9]);}" fullword ascii
    $s11 = "function LlmfIMQtcnMBChgEcZY(LuSzAGcEJUJWoNA,UQEfOWDyNaplJpXIHYfT){return String.fromCharCode(LuSzAGcEJUJWoNA,UQEfOWDyNaplJpXIHY" ascii
    $s12 = "var aclzQuslEkF=function(){return new ActiveXObject(dlAZmPgkFbU[0]);}();" fullword ascii
    $s13 = "function bXOzqTGVzeL(){return LAwQYz(dlAZmPgkFbU[10],[2,4,8,10],dlAZmPgkFbU[11]);}" fullword ascii
    $s14 = "var Jsdlyms = aclzQuslEkF.createtextfile(UUdkAC.ExpandEnvironmentStrings(dlAZmPgkFbU[2]+dlAZmPgkFbU[3])+String.fromCharCode(92)+" ascii
    $s15 = "function LlmfIMQtcnMBChgEcZY(LuSzAGcEJUJWoNA,UQEfOWDyNaplJpXIHYfT){return String.fromCharCode(LuSzAGcEJUJWoNA,UQEfOWDyNaplJpXIHY" ascii
    $s16 = "function SVAzfgaXpsYH(txhszOIxL,jNDBCCFqO) {var rmtLTfvO=[dlAZmPgkFbU[15]];txhszOIxL[rmtLTfvO[0]](jNDBCCFqO,0x1,0x0)}" fullword ascii
    $s17 = "function llIiftICHzQXq(pGBwIZHFpttlTsCvMtIVMY,gvgNqgL){return pGBwIZHFpttlTsCvMtIVMY.indexOf(gvgNqgL);}" fullword ascii
    $s18 = "function VSPDhkkIX(){return LAwQYz(dlAZmPgkFbU[12],[0,3,6],dlAZmPgkFbU[13]);}" fullword ascii
    $s19 = "dlAZmPgkFbU[4],true);" fullword ascii
    $s20 = "function Tp(TWbwlLJtnLKLoMzVoZIJ){return String.fromCharCode(TWbwlLJtnLKLoMzVoZIJ);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}