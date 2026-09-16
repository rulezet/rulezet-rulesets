rule sig_20160527_c07d9558ca21652a91982ffe5a5e0250 {
  meta:
    description = "datamaliciousorder - file 20160527_c07d9558ca21652a91982ffe5a5e0250.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b28ab596b6b0ce2af7bcb7335fa0f1f12bf8b1795297fcdd47034aeafb627cd"

  strings:
    $s1  = "function TNBTUArqMRAIkn() {return WScript;}function cwWJCeBaLX(){return rPhYFVKWk.ExpandEnvironmentStrings(zaaqR())}" fullword ascii
    $s2  = "function scAnTAx(tNunNKBWBWDzW) {var DuGbunB = dWQxPReyPTejoJqHad.join(jcKslCdoGlbpbzmVd[6]);var olvMxfprIEvEATXTE, jYlEKbyn, OK" ascii
    $s3  = "function KCadKo(uwSFYaMhPqa,nrnMDqTkcYKrZVXWF){return uwSFYaMhPqa.charAt(nrnMDqTkcYKrZVXWF);}" fullword ascii
    $s4  = "function scAnTAx(tNunNKBWBWDzW) {var DuGbunB = dWQxPReyPTejoJqHad.join(jcKslCdoGlbpbzmVd[6]);var olvMxfprIEvEATXTE, jYlEKbyn, OK" ascii
    $s5  = "YlEKbyn, OKOKEGnUytNBrFNfHBHevJk);} while (XMmhKYMI < tNunNKBWBWDzW.length);return FpxwlBvDV;}" fullword ascii
    $s6  = "var xMsjWQDvN=function(){return new ActiveXObject(jcKslCdoGlbpbzmVd[0]);}();" fullword ascii
    $s7  = "function aqJqpsOevPRtZGreagrqkHJ(YHpsuWFoUaBHfARRtRFizJBf,tzptPnckJkJNLuFigoBPc){return YHpsuWFoUaBHfARRtRFizJBf.indexOf(tzptPnc" ascii
    $s8  = "function dJcpkvTJyA(uANwTMhD,bPKDbbbMOYYls,prNQXXRnQWh){diRdC=uANwTMhD.split(prNQXXRnQWh);bgmOtTVaM = jcKslCdoGlbpbzmVd[14];for(" ascii
    $s9  = "vJk = kHJtGqJISOdQ & 0xff;if (FLEFixmNRSPfyQiOvvzxVkHs == 64) FpxwlBvDV += ye(olvMxfprIEvEATXTE);else if (IXwSMiWYlkUpZVojvJeHhl" ascii
    $s10 = "function ASrHlWiuQKfrK(){return dJcpkvTJyA(jcKslCdoGlbpbzmVd[12],[0,3,6],jcKslCdoGlbpbzmVd[13]);}" fullword ascii
    $s11 = "function aqJqpsOevPRtZGreagrqkHJ(YHpsuWFoUaBHfARRtRFizJBf,tzptPnckJkJNLuFigoBPc){return YHpsuWFoUaBHfARRtRFizJBf.indexOf(tzptPnc" ascii
    $s12 = "var gzknLC = xMsjWQDvN.createtextfile(rPhYFVKWk.ExpandEnvironmentStrings(jcKslCdoGlbpbzmVd[2]+jcKslCdoGlbpbzmVd[3])+String.fromC" ascii
    $s13 = "function cSbEzBi(ZtmdgqasLDCXo,JEVcjSfJb) {var nWzuteWEPfjpUQ=[jcKslCdoGlbpbzmVd[15]];ZtmdgqasLDCXo[nWzuteWEPfjpUQ[0]](JEVcjSfJb" ascii
    $s14 = "function dJcpkvTJyA(uANwTMhD,bPKDbbbMOYYls,prNQXXRnQWh){diRdC=uANwTMhD.split(prNQXXRnQWh);bgmOtTVaM = jcKslCdoGlbpbzmVd[14];for(" ascii
    $s15 = "harCode(92)+jcKslCdoGlbpbzmVd[4],true);" fullword ascii
    $s16 = "oYUFVBl=0;oYUFVBl<bPKDbbbMOYYls.length;oYUFVBl++) {bgmOtTVaM+=diRdC[bPKDbbbMOYYls[oYUFVBl]];}return bgmOtTVaM.substring(3,bgmOtT" ascii
    $s17 = "function ye(WgxpmMLiQNbqmOR){return String.fromCharCode(WgxpmMLiQNbqmOR);}" fullword ascii
    $s18 = "var rPhYFVKWk=function(){return TNBTUArqMRAIkn().CreateObject(jcKslCdoGlbpbzmVd[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s19 = "function ILrdfhVfNV(){return dJcpkvTJyA(jcKslCdoGlbpbzmVd[10],[2,4,8,10],jcKslCdoGlbpbzmVd[11]);}" fullword ascii
    $s20 = "function IHWLwkCzjQSWABWsBNvowwbK(GWjeWqrQhLGCOFqAwJtBr,XTjbCtt,bObbOjifc){return String.fromCharCode(GWjeWqrQhLGCOFqAwJtBr,XTjb" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}