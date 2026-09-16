rule sig_20160527_819640e48d32c0b4b6f9068433ba942d {
  meta:
    description = "datamaliciousorder - file 20160527_819640e48d32c0b4b6f9068433ba942d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f0344340421cbbee9f1f9c6cc7b23e796a422562144085109f924ae3b590d0c"

  strings:
    $s1  = "function NNBYhIuFEdPef() {return WScript;}function HVOpVBmUHV(){return JENcmjMBNZaTX.ExpandEnvironmentStrings(uOzkeM())}" fullword ascii
    $s2  = "function lqKXqSXTQgqebJXzz(kGpBVrxhhOXwUZGyhDKabNE,vvHNgAhovXFecj){return kGpBVrxhhOXwUZGyhDKabNE.charAt(vvHNgAhovXFecj);}" fullword ascii
    $s3  = "MAdxxJjQiblMGHRkaWcqs & 0xff;if (LIeAYSUeTsJuihG == 64) zZkYof += MR(DEALM);else if (yfRnMeatrKqENKnnSUO == 64) zZkYof += VjmUxY" ascii
    $s4  = "function HPjnTgSdZdgY(gMenBPbGiLzBR,JxOYVs,mskzUvKlP){MgmXIIgd=gMenBPbGiLzBR.split(mskzUvKlP);hLLDNSP = pinKZjVADKaIaJ[14];for(O" ascii
    $s5  = "ode(92)+pinKZjVADKaIaJ[4],true);" fullword ascii
    $s6  = "var JENcmjMBNZaTX=function(){return NNBYhIuFEdPef().CreateObject(pinKZjVADKaIaJ[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s7  = "function fGDhfiKl(lqUHIyGkjwdTN) {var NFzUALQYJJPbrpJNvTDuWb = QaVeoCksDaQOdWA.join(pinKZjVADKaIaJ[6]);var DEALM, UrgXSiicqxmhiW" ascii
    $s8  = "var rYjwsFKi=function(){return new ActiveXObject(pinKZjVADKaIaJ[0]);}();" fullword ascii
    $s9  = "function VjmUxYuQEbTgYCobOyhvKqS(JjhuFCTdvTHDSiIMU,vzkhBgjbrMnXEuKSeKmxMmX){return String.fromCharCode(JjhuFCTdvTHDSiIMU,vzkhBgj" ascii
    $s10 = "function fGDhfiKl(lqUHIyGkjwdTN) {var NFzUALQYJJPbrpJNvTDuWb = QaVeoCksDaQOdWA.join(pinKZjVADKaIaJ[6]);var DEALM, UrgXSiicqxmhiW" ascii
    $s11 = "function ilhoIAXcfQlsYW(FBZyskIB,uLEUaWAUm,jjRNWwGaFrWXaRbuFbuyc){return String.fromCharCode(FBZyskIB,uLEUaWAUm,jjRNWwGaFrWXaRbu" ascii
    $s12 = "uQEbTgYCobOyhvKqS(DEALM, UrgXSiicqxmhiWC);else zZkYof += ilhoIAXcfQlsYW(DEALM, UrgXSiicqxmhiWC, BAfLSrUxdNVYRwLSPSOXQzHk);} whil" ascii
    $s13 = "MkXa=0;OMkXa<JxOYVs.length;OMkXa++) {hLLDNSP+=MgmXIIgd[JxOYVs[OMkXa]];}return hLLDNSP.substring(3,hLLDNSP.length);}" fullword ascii
    $s14 = "var stvzR = rYjwsFKi.createtextfile(JENcmjMBNZaTX.ExpandEnvironmentStrings(pinKZjVADKaIaJ[2]+pinKZjVADKaIaJ[3])+String.fromCharC" ascii
    $s15 = "function JXvdRaAAnQvAIzFryvcqcL(UTlRiilUSyr,tntdzOvmBK){return UTlRiilUSyr.indexOf(tntdzOvmBK);}" fullword ascii
    $s16 = "function ilhoIAXcfQlsYW(FBZyskIB,uLEUaWAUm,jjRNWwGaFrWXaRbuFbuyc){return String.fromCharCode(FBZyskIB,uLEUaWAUm,jjRNWwGaFrWXaRbu" ascii
    $s17 = "function uOzkeM(){return HPjnTgSdZdgY(pinKZjVADKaIaJ[8],[1,5,7],pinKZjVADKaIaJ[9]);}" fullword ascii
    $s18 = "function qFOnhWg(){return HPjnTgSdZdgY(pinKZjVADKaIaJ[12],[0,3,6],pinKZjVADKaIaJ[13]);}" fullword ascii
    $s19 = "e (BEUtiuOfyTCrriG < lqUHIyGkjwdTN.length);return zZkYof;}" fullword ascii
    $s20 = "function VjmUxYuQEbTgYCobOyhvKqS(JjhuFCTdvTHDSiIMU,vzkhBgjbrMnXEuKSeKmxMmX){return String.fromCharCode(JjhuFCTdvTHDSiIMU,vzkhBgj" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}