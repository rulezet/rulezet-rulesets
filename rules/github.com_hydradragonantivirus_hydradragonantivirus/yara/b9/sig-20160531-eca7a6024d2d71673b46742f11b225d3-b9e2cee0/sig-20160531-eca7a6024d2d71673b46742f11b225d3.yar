rule sig_20160531_eca7a6024d2d71673b46742f11b225d3 {
  meta:
    description = "datamaliciousorder - file 20160531_eca7a6024d2d71673b46742f11b225d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d00e553c578527c616b41c96b70833b1cfbcf6c27b859b376c94109997a0aa6e"

  strings:
    $s1  = "var eWkrGiKz=function(){return WScript.CreateObject(kCxKcEpzSFpmeH[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function bJHMEaLP(echhPSYRsPTyUX,ZaanPdj){return echhPSYRsPTyUX.charAt(ZaanPdj);}" fullword ascii
    $s3  = "function flvcv(sLUkazSTaBikeqcl,xINVrQfJWimUPWzn,FpoEPBzHkWgtEyTArNPljD){return String.fromCharCode(sLUkazSTaBikeqcl,xINVrQfJWim" ascii
    $s4  = "function RxijJfalSEqzh(vvhbTmkLdXolL) {var rAXnkNRP = OAGCNMOoAbRjfxsyrLQRv.join(kCxKcEpzSFpmeH[7]);var hevJlcLUFVkUGz, DXVRedYK" ascii
    $s5  = "function JnVLJDolPK(sIYkpNjepK,lLmDsYTzC,yuaSEo){wJtZzc=sIYkpNjepK.split(yuaSEo);hIMxZWwzDyDP = kCxKcEpzSFpmeH[0];for(TlXDKVVTB=" ascii
    $s6  = "function nuJNiAD(){return JnVLJDolPK(kCxKcEpzSFpmeH[9],[1,5,7],kCxKcEpzSFpmeH[10]);}" fullword ascii
    $s7  = "function jghXDka(){return eWkrGiKz.ExpandEnvironmentStrings(nuJNiAD())}" fullword ascii
    $s8  = "(aLUcSDAwX,0x1,0x0)}function jVPFKiCEdkAquL(IlTqkElbWfIl,jZMAyiKv,DSMfEsCZbBzLc){var vXwEHE=IlTqkElbWfIl.createtextfile(jZMAyiKv" ascii
    $s9  = " if (UrQTXyVJdCZoeYGAzqMz == 64) QWqJfCwnbjZbsXo += qXcNYjxltyObarP(hevJlcLUFVkUGz, DXVRedYKvGXmDkqJk);else QWqJfCwnbjZbsXo += f" ascii
    $s10 = "function b(wKkNczvKd){return String.fromCharCode(wKkNczvKd);}" fullword ascii
    $s11 = "function CDaOt(kTMLxFEVoj,dxiUxYF){return kTMLxFEVoj.indexOf(dxiUxYF);}" fullword ascii
    $s12 = ">> 8 & 0xff;yTMLVUic = iXXtXrrHTtufzsyxwjDJm & 0xff;if (VLFfxClPNQtafPgxYYOgQqv == 64) QWqJfCwnbjZbsXo += b(hevJlcLUFVkUGz);else" ascii
    $s13 = "function qXcNYjxltyObarP(FuUfXKpeNIvpsDRHClKS,UlUoDpwuZrND){return String.fromCharCode(FuUfXKpeNIvpsDRHClKS,UlUoDpwuZrND);}" fullword ascii
    $s14 = "lvcv(hevJlcLUFVkUGz, DXVRedYKvGXmDkqJk, yTMLVUic);} while (kWQILB < vvhbTmkLdXolL.length);return QWqJfCwnbjZbsXo;}" fullword ascii
    $s15 = "(aLUcSDAwX,0x1,0x0)}function jVPFKiCEdkAquL(IlTqkElbWfIl,jZMAyiKv,DSMfEsCZbBzLc){var vXwEHE=IlTqkElbWfIl.createtextfile(jZMAyiKv" ascii
    $s16 = "function JnVLJDolPK(sIYkpNjepK,lLmDsYTzC,yuaSEo){wJtZzc=sIYkpNjepK.split(yuaSEo);hIMxZWwzDyDP = kCxKcEpzSFpmeH[0];for(TlXDKVVTB=" ascii
    $s17 = "var SfQUrWJ=function(){return new ActiveXObject(kCxKcEpzSFpmeH[1]);}();" fullword ascii
    $s18 = "function flvcv(sLUkazSTaBikeqcl,xINVrQfJWimUPWzn,FpoEPBzHkWgtEyTArNPljD){return String.fromCharCode(sLUkazSTaBikeqcl,xINVrQfJWim" ascii
    $s19 = "function SGHzY(){return JnVLJDolPK(kCxKcEpzSFpmeH[11],[2,4,8,10],kCxKcEpzSFpmeH[12]);}" fullword ascii
    $s20 = "0;TlXDKVVTB<lLmDsYTzC.length;TlXDKVVTB++) {hIMxZWwzDyDP+=wJtZzc[lLmDsYTzC[TlXDKVVTB]];}return hIMxZWwzDyDP.substring(3,hIMxZWwzD" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}