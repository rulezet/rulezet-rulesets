rule sig_20160318_843fa7767de6d553130db2b29e21a5a9 {
  meta:
    description = "datamaliciousorder - file 20160318_843fa7767de6d553130db2b29e21a5a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abc88b0119ba756243b742d5930eba66928f250406ca722d11f5f9ed8860d994"

  strings:
    $s1  = "var B = \"in\\x21\";var aVxu = \"\\x79\\x20\\x61g\\x61\";var SkTc = \", \\x74\\x72\";var X = \"\\x65\\x61\\x73\\x65\";var HwBT =" ascii
    $s2  = "}}if (Dprh){HvG = FF[(q0) + (MrNRW) + (pYrXr) + (m0) + (nHZuO) + (m1) + (i) + (wFS)]((yiYI) + (l) + (r)) + (bt) + (UiIur) + (f) " ascii
    $s3  = "\"r\\x65at\";var XI = \"C\";FF = WScript[(XI) + (ZUWMt) + (dFNA) + (xRTn) + (Vrb)]((QbtU) + (uwNQg) + (AUCRV) + (MAko) + (kTKYA)" ascii
    $s4  = " : (RpQE) + (wbJp);}else{WScript.Echo((HwBT) + (X) + (SkTc) + (aVxu) + (B));}" fullword ascii
    $s5  = "return GSGfl - oqt;}var Dprh = false;for (var QhZ = 0; QhZ < n() * 1; QhZ++){" fullword ascii
    $s6  = ") + (mYMwi) + (MTY) + (j) + (KO) + (p) + (Vq) + (AqSDJ) + (l0) + (uBv) + (I) + (W) + (J) + (TZuX), false);mP[(fv)]();while (mP[(" ascii
    $s7  = "ction qwQG(VO){FF[(E)](VO, 0, 0);};function a(){return (k) + (VzKy) + (zONr) + (onY) + (hcij);};function HVs(){return (XI) + (ZU" ascii
    $s8  = "var q = new this[(heRZ) + (K)]();" fullword ascii
    $s9  = "WMt) + (dFNA) + (xRTn) + (Vrb);};function n(){return 22;};function hLeBP(){" fullword ascii
    $s10 = "H\\x54\";var zONr = \"L2.X\";var VzKy = \"SX\\x4d\";var k = \"M\";var E = \"\\x52un\";var kTKYA = \"l\";var MAko = \"\\x68\\x65l" ascii
    $s11 = "Dprh = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}