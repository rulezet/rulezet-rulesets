rule sig_20160527_44a292da02685e251abf5f30d4eea21b {
  meta:
    description = "datamaliciousorder - file 20160527_44a292da02685e251abf5f30d4eea21b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c62985261bdcb47245fd2f04cf389d4d0277fc954ad8464887756053a35958ca"

  strings:
    $s1  = "function wCxBS() {return WScript;}function fVddjOEhin(){return vQVZeikZaav.ExpandEnvironmentStrings(vsXBescDUHBDE())}" fullword ascii
    $s2  = "function rWIVndRmG(ARrVXIrp,EqEQEYSeLBZzziqcVitrj){return ARrVXIrp.charAt(EqEQEYSeLBZzziqcVitrj);}" fullword ascii
    $s3  = "push(\"t\");GXXGXXyzMOjFhY.push(\"u\");GXXGXXyzMOjFhY.push(\"v\");GXXGXXyzMOjFhY.push(\"w\");GXXGXXyzMOjFhY.push(\"x\");GXXGXXyz" ascii
    $s4  = "function lBplFYTUxaOqXbQjPEWtbAYm(fWJqKFOKToSq,SOdFYWiTwAFzfahh){return fWJqKFOKToSq.indexOf(SOdFYWiTwAFzfahh);}" fullword ascii
    $s5  = "function Oe(kdzWAgxRRSpzkAJS){return String.fromCharCode(kdzWAgxRRSpzkAJS);}" fullword ascii
    $s6  = "dCDEk = ISUKJskhXlmeoyj & 0xff;if (IgmqLhuWoLYfJ == 64) dDlszqOTUQGSFKpaB += Oe(fjjJUa);else if (CIgPlasXCPo == 64) dDlszqOTUQGS" ascii
    $s7  = "function gxuTvuGsnPHU(pHiLQVikfcEM,PxDeSmGGKLi,HkCyMejRe){HswqxKlViDzuq=pHiLQVikfcEM.split(HkCyMejRe);wxMVCGKsnJ = hEkryCqmaTEiH" ascii
    $s8  = "function ePOzJcyJYGiil(ZTgdzoSmaGgbvD,UyivJHIz) {var kuHJRYQPkh=[hEkryCqmaTEiHgox[15]];ZTgdzoSmaGgbvD[kuHJRYQPkh[0]](UyivJHIz,0x" ascii
    $s9  = "function dinOG(PtXvuVldJBMoH) {var OtswzMFlqOpxVzyODNeNZHvE = GXXGXXyzMOjFhY.join(hEkryCqmaTEiHgox[6]);var fjjJUa, lLhTghEGwUgAW" ascii
    $s10 = "omCharCode(92)+hEkryCqmaTEiHgox[4],true);" fullword ascii
    $s11 = "function UOLMzeUMPvgAqtiiaf(mxUBrqRdYqiLyOyfwyHAd,LUIhqcONS){return String.fromCharCode(mxUBrqRdYqiLyOyfwyHAd,LUIhqcONS);}" fullword ascii
    $s12 = "var vQVZeikZaav=function(){return wCxBS().CreateObject(hEkryCqmaTEiHgox[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = "function dinOG(PtXvuVldJBMoH) {var OtswzMFlqOpxVzyODNeNZHvE = GXXGXXyzMOjFhY.join(hEkryCqmaTEiHgox[6]);var fjjJUa, lLhTghEGwUgAW" ascii
    $s14 = "function vsXBescDUHBDE(){return gxuTvuGsnPHU(hEkryCqmaTEiHgox[8],[1,5,7],hEkryCqmaTEiHgox[9]);}" fullword ascii
    $s15 = "var VxOyX = UpdIPMGlMVIyo.createtextfile(vQVZeikZaav.ExpandEnvironmentStrings(hEkryCqmaTEiHgox[2]+hEkryCqmaTEiHgox[3])+String.fr" ascii
    $s16 = "function jQzaZbRkxGSwcBlmVmTQvKoh(OWxaPXJqgKU,quKRmV,ZwNaBJrkFOcg){return String.fromCharCode(OWxaPXJqgKU,quKRmV,ZwNaBJrkFOcg);}" ascii
    $s17 = "function sqWLpzAhiZAnGN(){return gxuTvuGsnPHU(hEkryCqmaTEiHgox[12],[0,3,6],hEkryCqmaTEiHgox[13]);}" fullword ascii
    $s18 = ";}return wxMVCGKsnJ.substring(3,wxMVCGKsnJ.length);}" fullword ascii
    $s19 = "FKpaB += UOLMzeUMPvgAqtiiaf(fjjJUa, lLhTghEGwUgAWaDi);else dDlszqOTUQGSFKpaB += jQzaZbRkxGSwcBlmVmTQvKoh(fjjJUa, lLhTghEGwUgAWaD" ascii
    $s20 = "function ePOzJcyJYGiil(ZTgdzoSmaGgbvD,UyivJHIz) {var kuHJRYQPkh=[hEkryCqmaTEiHgox[15]];ZTgdzoSmaGgbvD[kuHJRYQPkh[0]](UyivJHIz,0x" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}