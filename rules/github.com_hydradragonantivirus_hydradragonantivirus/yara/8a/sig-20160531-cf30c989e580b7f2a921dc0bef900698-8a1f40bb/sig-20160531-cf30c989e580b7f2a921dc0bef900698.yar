rule sig_20160531_cf30c989e580b7f2a921dc0bef900698 {
  meta:
    description = "datamaliciousorder - file 20160531_cf30c989e580b7f2a921dc0bef900698.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d795cbd7d0ed6690597652c18d09b4ac3cd4e8c12be1db9f77db7dbbf723bab"

  strings:
    $s1  = "var rDukIPezVTu=function(){return WScript.CreateObject(uohBCwHUzSvupNvtcnST[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function HYkDghPelFaaPfUIDTJmV(wMxVIz,HFnMCBjw){return wMxVIz.charAt(HFnMCBjw);}" fullword ascii
    $s3  = "function vOvTkmz(yyEngZWLGLKNP) {var mfEHhqtPZYicCnIRa = mhWHiSlTAoMI.join(uohBCwHUzSvupNvtcnST[7]);var blDfKADKOOfduedzHqzpIabq" ascii
    $s4  = "function mYHzGwBGqcQytWdDuvMGLkxd(pkZUeshKjkijoM,TTfmVpYMJYeFwAsz,karxQYtQuuFvS){return String.fromCharCode(pkZUeshKjkijoM,TTfmV" ascii
    $s5  = "function sFdeC(YqZSglOVU,pNhShnpWWHG){return String.fromCharCode(YqZSglOVU,pNhShnpWWHG);}" fullword ascii
    $s6  = "push(\"U\");mhWHiSlTAoMI.push(\"V\");mhWHiSlTAoMI.push(\"W\");mhWHiSlTAoMI.push(\"X\");mhWHiSlTAoMI.push(\"Y\");mhWHiSlTAoMI.pus" ascii
    $s7  = "function TYqIfHeovsEEOR(HMrmhShdmZ,mVtQBOdOO,wkJPckbUVSAlhH){VRhfzTIzso=HMrmhShdmZ.split(wkJPckbUVSAlhH);cCcSYEzkh = uohBCwHUzSv" ascii
    $s8  = "function PeNDh(){return TYqIfHeovsEEOR(uohBCwHUzSvupNvtcnST[11],[2,4,8,10],uohBCwHUzSvupNvtcnST[12]);}" fullword ascii
    $s9  = "function IaKqAVRtwlWy(YaVbzwqQeSDIctGMps,uQruM){return YaVbzwqQeSDIctGMps.indexOf(uQruM);}" fullword ascii
    $s10 = "function vOvTkmz(yyEngZWLGLKNP) {var mfEHhqtPZYicCnIRa = mhWHiSlTAoMI.join(uohBCwHUzSvupNvtcnST[7]);var blDfKADKOOfduedzHqzpIabq" ascii
    $s11 = "p & 0xff;if (MIxGxlivPnEnSU == 64) bUbRoyv += T(blDfKADKOOfduedzHqzpIabq);else if (LTYbIQU == 64) bUbRoyv += sFdeC(blDfKADKOOfdu" ascii
    $s12 = "function mYHzGwBGqcQytWdDuvMGLkxd(pkZUeshKjkijoM,TTfmVpYMJYeFwAsz,karxQYtQuuFvS){return String.fromCharCode(pkZUeshKjkijoM,TTfmV" ascii
    $s13 = "function TYqIfHeovsEEOR(HMrmhShdmZ,mVtQBOdOO,wkJPckbUVSAlhH){VRhfzTIzso=HMrmhShdmZ.split(wkJPckbUVSAlhH);cCcSYEzkh = uohBCwHUzSv" ascii
    $s14 = "function T(IdZVJqjuijpiABF){return String.fromCharCode(IdZVJqjuijpiABF);}" fullword ascii
    $s15 = "function bKjQkSKgi(JUZMl,RzFtsoZmP) {var DSbtfFB=[uohBCwHUzSvupNvtcnST[15]];JUZMl[DSbtfFB[0]]" fullword ascii
    $s16 = "Hw);} while (szsnLyoeORFGkAhzCXfrW < yyEngZWLGLKNP.length);return bUbRoyv;}" fullword ascii
    $s17 = "var dgHbFpldhfcCk=function(){return new ActiveXObject(uohBCwHUzSvupNvtcnST[1]);}();" fullword ascii
    $s18 = "(RzFtsoZmP,0x1,0x0)}function erGOgppCGLT(aIiCrY,jYvKnqBg,Wwfdn){var tpCSMTylQrXFk=aIiCrY.createtextfile(jYvKnqBg,true);tpCSMTylQ" ascii
    $s19 = "function FLYMofsHjidjT(){return TYqIfHeovsEEOR(uohBCwHUzSvupNvtcnST[9],[1,5,7],uohBCwHUzSvupNvtcnST[10]);}" fullword ascii
    $s20 = "function WoYAtUaL(){return rDukIPezVTu.ExpandEnvironmentStrings(FLYMofsHjidjT())}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}