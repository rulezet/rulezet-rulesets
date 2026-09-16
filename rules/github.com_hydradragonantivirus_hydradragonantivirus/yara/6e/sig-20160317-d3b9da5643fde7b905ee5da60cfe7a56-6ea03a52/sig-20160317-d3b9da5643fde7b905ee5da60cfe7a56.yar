rule sig_20160317_d3b9da5643fde7b905ee5da60cfe7a56 {
  meta:
    description = "datamaliciousorder - file 20160317_d3b9da5643fde7b905ee5da60cfe7a56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2c543d57133593b0466e2a5575451f4625419f7428112d5f584216f3ad2c07e"

  strings:
    $s1 = "var ek = \"\\x67a\\x69n!\";var KRJt = \" a\";var N0 = \"\\x74ry\";var UVi = \"\\x73\\x65,\\x20\";var Yga = \"Plea\";var hAAWr = " ascii
    $s2 = "}}if (OHQ){CCoYo = P[(yh) + (vxbnZ) + (UhJeb) + (pP) + (H) + (gXWYy) + (Y)]((lW) + (ATdl)) + (LUu) + (Ob) + (gUvJ) + (UDOiz) + (" ascii
    $s3 = "g) + (qKWg) + (UldJ) + (oGd) + (PNkF) + OHQ ? (m0) + (Rm) : (Si) + (Df) + (hAAWr);}else{WScript.Echo((Yga) + (UVi) + (N0) + (KRJ" ascii
    $s4 = "return rd - iRnT;}var OHQ = false;for (var eTY = 0; eTY < 10; eTY++){" fullword ascii
    $s5 = " (ofw) + (D);};function iKd(){return (B) + (WyCE) + (mgEO) + (F) + (YjWba) + (ILfYg);};function iY(){return 22;};function PgYv()" ascii
    $s6 = "Fq) + (pA) + (TWN) + (veWr) + (eyGZB) + (DDu) + (Rxga) + (f) + (LT) + (Dep), false);Typ[(svpzP) + (WRsCU)]();while (Typ[(v) + (L" ascii
    $s7 = "ILfYg)]((m) + (NE) + (BAUsK) + (JDeZY) + (oAne));function e(L){P[(R)](L, 0, 0);};function JqYhj(){return (cRY) + (C) + (FcSwS) +" ascii
    $s8 = "var GhlKG = new this[(YcsZx)]();" fullword ascii
    $s9 = "OHQ = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}