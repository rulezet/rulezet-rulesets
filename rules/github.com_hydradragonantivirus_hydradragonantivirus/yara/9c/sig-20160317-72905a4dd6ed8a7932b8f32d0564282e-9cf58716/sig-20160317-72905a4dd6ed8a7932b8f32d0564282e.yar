rule sig_20160317_72905a4dd6ed8a7932b8f32d0564282e {
  meta:
    description = "datamaliciousorder - file 20160317_72905a4dd6ed8a7932b8f32d0564282e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "003e4b4ce7c578c746be1483a558e603d8c379d2dec47f2a85b972e39579b520"

  strings:
    $s1 = "var BZo = \"ain\\x21\";var eQ = \" ag\";var q = \"y\";var lg = \"\\x74r\";var WKLB = \"\\x65, \";var DNmq = \"sJ\".charAt(0);var" ascii
    $s2 = "}}if (BvkB){CM = J[(CDJv) + (lA) + (eWq) + (ZK) + (mI) + (pT) + (kzumr) + (jPWdr) + (by) + (GNs)]((obnPp) + (X) + (Tmfak)) + (rt" ascii
    $s3 = ", false);KtLm[(gB)]();while (KtLm[(vSL) + (H) + (jove)] < 4 ) {WScript[(PiF) + (wZzh) + (g)](iVJe() * 10)};VHAwg = WScript[YX()]" ascii
    $s4 = "YWx) + (vWt) : (zCo) + (W0) + (DlQuq);}else{WScript.Echo((v0) + (DNmq) + (WKLB) + (lg) + (q) + (eQ) + (BZo));}" fullword ascii
    $s5 = "return M - kD;}var BvkB = false;for (var bViND = 0; bViND < iVJe() * 1; bViND++){" fullword ascii
    $s6 = "nction KTOMR(cg){J[(RXB) + (c)](cg, 0, 0);};function DJNzo(){return (Kv) + (gDE) + (r) + (bu) + (Cr);};function YX(){return (AdX" ascii
    $s7 = "var vrfQ = new this[(bFE) + (rfU) + (ZFqZb)]();" fullword ascii
    $s8 = "p) + (WJx) + (gC) + (KdA) + (ekTVe) + (fAfW) + (Jah) + (WmvtS);};function iVJe(){return 22;};function Biy(){" fullword ascii
    $s9 = "BvkB = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}