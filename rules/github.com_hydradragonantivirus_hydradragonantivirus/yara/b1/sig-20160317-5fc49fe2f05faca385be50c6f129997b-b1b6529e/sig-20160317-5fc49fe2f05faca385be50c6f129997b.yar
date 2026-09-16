rule sig_20160317_5fc49fe2f05faca385be50c6f129997b {
  meta:
    description = "datamaliciousorder - file 20160317_5fc49fe2f05faca385be50c6f129997b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22aed988cb5ab5c1820d941101b7b11575e832f382c25f09181f6fe33b7306dd"

  strings:
    $s1 = "var D = \"\\x6e!\";var ZKiOL = \"gai\";var PGd = \"y a\";var vkxbE = \"\\x65\\x2c\\x20\\x74r\";var RB = \"\\x50le\\x61\\x73\";va" ascii
    $s2 = "}}if (SDoI){s = eSm[(f) + (de) + (KIXT) + (ryI) + (a0) + (PH) + (icx)]((WGD) + (Fw) + (OR) + (cHQds)) + (C) + (UWHrM) + (g) + (I" ascii
    $s3 = "return G - q;}var SDoI = false;for (var cvz = 0; cvz < 10; cvz++){" fullword ascii
    $s4 = "var nJqwh = new this[(R) + (E)]();" fullword ascii
    $s5 = " + (pJJhk) + (iO) + (QGIj) + (uZBwz) + (Lgjs) + (VoK) + (ecE) + (R0) + SDoI ? (lxjzt) + (XXKUG) : (o1) + (j0) + (UtmMW);}else{WS" ascii
    $s6 = " + (hngQc) + (d);};function v(){return (vSke) + (o0) + (DvPXr) + (Iix);};function wsa(){return 22;};function o(){" fullword ascii
    $s7 = " + (l) + (otSDN) + (ti) + (Rd) + (FLI) + (Xj) + (Uboe) + (xOTk) + (dAfRA) + (O) + (vAK) + (eYSFX), false);J[(pbQI) + (LBb)]();wh" ascii
    $s8 = "+ (DvPXr) + (Iix)]((VUnQc) + (GuOyO) + (Sx) + (ade));function xmORx(ICQ){eSm[(Yo)](ICQ, 0, 0);};function jzJB(){return (N) + (k)" ascii
    $s9 = "SDoI = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}