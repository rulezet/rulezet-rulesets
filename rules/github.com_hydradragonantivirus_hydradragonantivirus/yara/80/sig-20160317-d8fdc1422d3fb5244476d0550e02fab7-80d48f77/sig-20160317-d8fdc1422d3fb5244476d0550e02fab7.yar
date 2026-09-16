rule sig_20160317_d8fdc1422d3fb5244476d0550e02fab7 {
  meta:
    description = "datamaliciousorder - file 20160317_d8fdc1422d3fb5244476d0550e02fab7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b31feb21995782ece9f796b9ccd4246cac466af94daad92b1d7da90f2c381faa"

  strings:
    $s1  = "var cQ = \"n!\";var tUE = \"\\x61i\";var jp = \"a\\x67\";var nKHGM = \"y \";var LWkw = \"e, \\x74r\";var E0 = \"Pleas\";var LqU " ascii
    $s2  = "alse);JyjEP[(fA) + (vZXZ)]();while (JyjEP[(VNLm) + (w) + (zowHz) + (lHv) + (jG)] < 4 ) {WScript[(Up) + (qfkgX)](ckoz() * 10)};Kx" ascii
    $s3  = "(kZSd) + (bbVXK) : (uVCp) + (i) + (w0) + (AO) + (LqU);}else{WScript.Echo((E0) + (LWkw) + (nKHGM) + (jp) + (tUE) + (cQ));}" fullword ascii
    $s4  = "ar G = \"\\x43re\\x61\";u = WScript[(G) + (HjQR) + (txUO) + (zUd)]((oZg) + (KIo) + (a) + (VhKAC));function AQp(MGr){u[(hTU)](MGr" ascii
    $s5  = "}}if (LH){bjQ = u[(gv) + (v0) + (qkmf) + (fKYDz) + (RfH) + (OE) + (BAZl) + (NOK) + (FNxLr) + (CdXb)]((GtOs) + (SpOw) + (QlPy)) +" ascii
    $s6  = "return k - L;}var LH = false;for (var muIH = 0; muIH < ckoz() * 1; muIH++){" fullword ascii
    $s7  = " 0);};function R(){return (Dwn) + (Dk) + (V) + (HIFO);};function Zss(){return (G) + (HjQR) + (txUO) + (zUd);};function ckoz(){re" ascii
    $s8  = "var LrJT = new this[(F)]();" fullword ascii
    $s9  = "turn 22;};function h(){" fullword ascii
    $s10 = "LH = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}