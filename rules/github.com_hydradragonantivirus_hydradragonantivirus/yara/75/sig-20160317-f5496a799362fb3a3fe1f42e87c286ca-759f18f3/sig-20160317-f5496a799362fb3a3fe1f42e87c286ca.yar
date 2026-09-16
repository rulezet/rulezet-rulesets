rule sig_20160317_f5496a799362fb3a3fe1f42e87c286ca {
  meta:
    description = "datamaliciousorder - file 20160317_f5496a799362fb3a3fe1f42e87c286ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b403e6963522be96ec97f2d3246e8308d5c36d4e3ef1a7f4e23470cb14f0e701"

  strings:
    $x1 = "var VlGt = \"8ie!tx2r7\".charAt(3);var AOfK = \"ai\\x6e\";var n = \"y ag\";var SrMr = \"TqrE\".charAt(2);var oxTye = \"\\x2c t\"" ascii
    $s2 = "}}if (Eqll){sdQ = wLX[(Npk) + (X) + (vorUj) + (e) + (nQ) + (OueMr)]((c) + (dCdVs) + (ynEE) + (rOLK) + (E)) + (zxEjI) + (Bqtbl) +" ascii
    $s3 = "j) + (VNS) + (mDcnz) + (SMToe);}else{WScript.Echo((hrV) + (Bov) + (oxTye) + (SrMr) + (n) + (AOfK) + (VlGt));}" fullword ascii
    $s4 = "return zWa - AYJnu;}var Eqll = false;for (var lW = 0; lW < S() * 1; lW++){" fullword ascii
    $s5 = " (xEpDZ) + (i) + (mM) + (zlL) + (W) + (VRI));function uQIV(fpuQb){wLX[(mTb)](fpuQb, 0, 0);};function YxWuy(){return (k) + (b) + " ascii
    $s6 = "(JCD) + (Z);};function EJUy(){return (t) + (BT) + (bbwU) + (pPT);};function S(){return 22;};function s(){" fullword ascii
    $s7 = " (F) + (YHBS) + (qWGg) + (X0) + (eUCv) + (IKtNj) + (J) + (f) + (JhPkX) + (L) + (gODRL) + (ySGI), false);IUMw[(xk) + (tgi)]();whi" ascii
    $s8 = "var d = new this[(KAX) + (tu) + (i0)]();" fullword ascii
    $s9 = "Eqll = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}