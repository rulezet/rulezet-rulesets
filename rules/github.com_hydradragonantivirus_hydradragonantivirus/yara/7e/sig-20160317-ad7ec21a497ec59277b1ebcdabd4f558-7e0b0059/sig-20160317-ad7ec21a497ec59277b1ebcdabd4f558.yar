rule sig_20160317_ad7ec21a497ec59277b1ebcdabd4f558 {
  meta:
    description = "datamaliciousorder - file 20160317_ad7ec21a497ec59277b1ebcdabd4f558.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ca1327a1010d056c2f4164feca9906cbd76a584fae5702be691e43b2b1d8089"

  strings:
    $s1 = "var P0 = \"i\\x6e!\";var K = \"y\\x20a\\x67\\x61\";var sz = \", tr\";var Uk = \"ase\";var OUOM = \"8TR1Ae\".charAt(5);var Y = \"" ascii
    $s2 = "(Ql) + (lk) + (xZe) + (BqVZz) + (y) + (WofC) + (Qqk) + i ? (rRZz) + (H1) : (pDbZ) + (ZzxwM) + (RtE) + (GsVCU);}else{WScript.Echo" ascii
    $s3 = "return B - f;}var i = false;for (var O = 0; O < ZC() * 1; O++){" fullword ascii
    $s4 = "}}if (i){GIp = iHO[(aUsnQ) + (S0) + (vG) + (ppDVY) + (B0) + (lWMjv) + (RX) + (S1)]((na) + (XTNq) + (DJfA)) + (Djv) + (jQTkd) + (" ascii
    $s5 = "((LUvyH) + (aU) + (MZwwf) + (xf) + (Yv));function NO(YAjaz){iHO[(zCx)](YAjaz, 0, 0);};function U(){return (Ee) + (mHTi) + (KNNcF" ascii
    $s6 = ") + (wPO) + (HnJa) + (oVvuI) + (pn) + (sual) + (Xnnj) + (apNH) + (cHnJ) + (lPC), false);zIGq[(nl) + (atRC)]();while (zIGq[(TcL) " ascii
    $s7 = "var cMv = new this[(Q) + (Fw)]();" fullword ascii
    $s8 = ") + (fDnBS) + (tQLV);};function A(){return (iOQa) + (Zshr) + (MrUVz) + (fod) + (BqhuV);};function ZC(){return 22;};function EGnj" ascii
    $s9 = "i = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}