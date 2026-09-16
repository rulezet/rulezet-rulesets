rule sig_20160317_c606e89ab21d34d876d2a7ad2a2e2f59 {
  meta:
    description = "datamaliciousorder - file 20160317_c606e89ab21d34d876d2a7ad2a2e2f59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3edd66f61852014652702ab48cf982256a962c6740cf45762dcab21b589c9acd"

  strings:
    $s1  = "var CMTp = \"\\x6e!\";var vWRT = \"\\x67\\x61i\";var tu = \"r\\x79 a\";var Y0 = \"\\x73\\x65\\x2c\\x20\\x74\";var u = \"\\x50\\x" ascii
    $s2  = "+ (ywI) + (US) + (dntV) + (ytHm) + (ty) + (Qg) + Dh ? (DQjua) + (kslq) + (e) + (fCL) : (PLVM) + (wigS) + (knEpp);}else{WScript.E" ascii
    $s3  = "return Lr - CS;}var Dh = false;for (var WvH = 0; WvH < U() * 1; WvH++){" fullword ascii
    $s4  = "}}if (Dh){U0 = sj[(eTbMh) + (bNVql) + (EioA) + (TDL) + (H0) + (HAv) + (bhoVf) + (nC)]((O1) + (LW)) + (dj) + (It) + (ft) + (WItc)" ascii
    $s5  = "eturn (dPzgl) + (eN) + (kCZ) + (XmSX) + (M);};function T(){return (Y) + (n) + (ZF) + (Dy) + (LG) + (ZPy) + (o) + (IZTcd);};funct" ascii
    $s6  = "var Lpk = new this[(Md) + (Dfj) + (nxMK)]();" fullword ascii
    $s7  = "y) + (o) + (IZTcd)]((ww) + (AnQNa) + (Za) + (sls) + (n0) + (kBBV));function j(vT){sj[(PPX) + (eTi)](vT, 0, 0);};function yjX(){r" ascii
    $s8  = " (LeGP) + (JMDt) + (mmt) + (oS) + (db) + (AuNgM) + (fTbJx) + (TsfMa) + (WDt) + (pSG), false);O[(Wu)]();while (O[(PBk) + (wia) + " ascii
    $s9  = "ion U(){return 22;};function i(){" fullword ascii
    $s10 = "Dh = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}