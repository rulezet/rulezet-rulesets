rule sig_20160317_50b83e1177308c922a1b082aec8b751c {
  meta:
    description = "datamaliciousorder - file 20160317_50b83e1177308c922a1b082aec8b751c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c9b97eabcd196f6e1b0f7bc506e6f0f7f026ecb29e270e1680f00f7e271b4f9"

  strings:
    $s1  = "var KBLf = \"in!\";var IKKAx = \"\\x67a\";var MhPAe = \"y\\x20a\";var g = \"e, t\\x72\";var YMuV = \"FeMTsaOi\".charAt(4);var k0" ascii
    $s2  = " (vj) + (war) + (sfVU) + (gIfa) + (v) + (KUgZ) + (QmqO) + (IMcpJ) + (Kpwh) + JRLPV ? (IYZ) + (InN) : (Wv) + (Sz);}else{WScript.E" ascii
    $s3  = "}}if (JRLPV){vO = gDmW[(QUav) + (mGjO) + (l) + (rDqn) + (hQmJ) + (UI) + (gLWD)]((ArW) + (jUTHH) + (olV)) + (TNaQ) + (mSp) + (yAY" ascii
    $s4  = "]();while (DiUt[(OoYJ) + (B)] < 4 ) {WScript[(XJv)](pRmQ() * 10)};VosWm = WScript[j()]((oww) + (Ju) + (sfop) + (Uoe));VosWm[((p)" ascii
    $s5  = "return Minr - n;}var JRLPV = false;for (var jXG = 0; jXG < pRmQ() * 1; jXG++){" fullword ascii
    $s6  = "return (o) + (krkcs) + (jmfqp) + (xhi) + (vn) + (ba) + (Xc);};function j(){return (pnug) + (LP) + (Ex) + (MHsV);};function pRmQ(" ascii
    $s7  = "vLv), (YVj) + (GVxS) + (VsGik) + (ghgFE) + (aNYdI) + (cGspq) + (DwU) + (n1) + (tncc) + (FZQMV), false);DiUt[(UZsZ) + (wS) + (fq)" ascii
    $s8  = "pnug) + (LP) + (Ex) + (MHsV)]((nDYZE) + (OvBH) + (Gt));function HUlgR(mhQaF){gDmW[(sDe) + (MFT)](mhQaF, 0, 0);};function Skhp(){" ascii
    $s9  = "var sL = new this[(QjJiu)]();" fullword ascii
    $s10 = "){return 22;};function tsSz(){" fullword ascii
    $s11 = "JRLPV = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}