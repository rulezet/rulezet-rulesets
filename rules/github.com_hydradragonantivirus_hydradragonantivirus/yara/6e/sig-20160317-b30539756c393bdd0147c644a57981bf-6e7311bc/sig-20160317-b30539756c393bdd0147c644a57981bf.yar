rule sig_20160317_b30539756c393bdd0147c644a57981bf {
  meta:
    description = "datamaliciousorder - file 20160317_b30539756c393bdd0147c644a57981bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f678f4e82f78db52327e46f060ec8e4a7ab0d1f54d4f60cfa600fddfbd7e5f1"

  strings:
    $s1 = "var QNX = \"n!\";var BIe = \"ga\\x69\";var wiaD = \"ry\\x20a\";var dv = \"e,\\x20t\";var gzFj = \"\\x50\\x6cea\\x73\";var fQC = " ascii
    $s2 = "(v) + (dcht) + (mHcjf) + (fQC);}else{WScript.Echo((gzFj) + (dv) + (wiaD) + (BIe) + (QNX));}" fullword ascii
    $s3 = " + (g) + (V) + (OMKXU) + (G), false);K[(qDW) + (hpr)]();while (K[(CEKT) + (t) + (HGr) + (uXDEk) + (n1)] < 4 ) {WScript[(PUaui)](" ascii
    $s4 = "return Xq - B;}var X = false;for (var W = 0; W < auXH() * 1; W++){" fullword ascii
    $s5 = "}}if (X){E = JskWk[(o) + (Zkf) + (b) + (uI) + (pzXSu) + (Tb) + (ZTkBh)]((ED) + (qwok)) + (T) + (QiqUW) + (U) + (DJqLV) + (clBe) " ascii
    $s6 = "var kkFjn = new this[(RH) + (Cf) + (Uv)]();" fullword ascii
    $s7 = " (xrw) + (MZj) + (HO) + (vsx);};function R(){return (rn) + (oC) + (vJ) + (AHUQ);};function auXH(){return 22;};function QX(){" fullword ascii
    $s8 = "(AHUQ)]((n) + (tmueQ) + (k) + (OS) + (gP) + (EHw));function L(tdnt){JskWk[(VZheR)](tdnt, 0, 0);};function whca(){return (jZOz) +" ascii
    $s9 = "X = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}