rule sig_20160317_d8cc25eba12783ddeb05ba0b273663c8 {
  meta:
    description = "datamaliciousorder - file 20160317_d8cc25eba12783ddeb05ba0b273663c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32203e6b6ed13e6d742eae57dc683f9bd0941626caa79703b037011320dd3e2d"

  strings:
    $s1  = "var vgJF = \"ga\\x69\\x6e!\";var oDeuV = \"Efqar76\".charAt(3);var LWJ = \" try\\x20\";var fJEcR = \"se,\";var S = \"Plea\";var " ascii
    $s2  = "NO);}else{WScript.Echo((S) + (fJEcR) + (LWJ) + (oDeuV) + (vgJF));}" fullword ascii
    $s3  = "+ (saoD)]();while (SiYJZ[(fkWSO) + (ohsj) + (SdvpV)] < 4 ) {WScript[(pNrjJ) + (RfB)](d() * 10)};GeLZ = WScript[weYwD()]((kuq) + " ascii
    $s4  = "Cr\";EbBUf = WScript[(vtaBs) + (I) + (pHI)]((RP) + (eu) + (MRaS) + (umPq) + (FGkm) + (F));function eKM(q){EbBUf[(loEo) + (DcIc)]" ascii
    $s5  = "}}if (cf){t = EbBUf[(sfMiM) + (uIlb) + (EkPku) + (NVeUA) + (r) + (R) + (vjP) + (ve) + (Nc) + (mWz) + (o) + (VHoH)]((YzXM) + (e) " ascii
    $s6  = "return WefpI - a;}var cf = false;for (var NL = 0; NL < d() * 1; NL++){" fullword ascii
    $s7  = " = \"C0eef8ASJ\".charAt(4);var BnX = \"\\x68isd\";var TEEm = \"u\";var pKlu = \"df\\x79a\";var Vi = \"7o\\x67s\";var giMl = \"sd" ascii
    $s8  = "q, 0, 0);};function MHHnO(){return (mL) + (J) + (mMEna) + (Gr) + (OWEgL);};function weYwD(){return (vtaBs) + (I) + (pHI);};funct" ascii
    $s9  = "+ (thm) + (giMl) + (Vi) + (pKlu) + (TEEm) + (BnX) + (kpgLx) + cf ? (cwAF) + (pNt) + (HK) + (oPvL) : (EPBeJ) + (qG) + (eoU) + (SY" ascii
    $s10 = "C) + (F0), (htiBI) + (L0) + (hB) + (VlZMz) + (XK) + (fRn) + (yt) + (QhaX) + (OTNBR) + (tABaX) + (HJZ) + (kXn), false);SiYJZ[(x) " ascii
    $s11 = "ion d(){return 22;};function hxX(){" fullword ascii
    $s12 = "var ZDt = new this[(jFv)]();" fullword ascii
    $s13 = "cf = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}