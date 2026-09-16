rule sig_20160317_b507bd1b184cfdf57ec793d203be27b1 {
  meta:
    description = "datamaliciousorder - file 20160317_b507bd1b184cfdf57ec793d203be27b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8a23504b8800f62c19579d57182f89b04e827e9c78a6fd9e11bcb85e6aab6c3"

  strings:
    $s1 = "var VNH = \"\\x61\\x69\\x6e!\";var IBEpU = \"ag\";var Sct = \"ry\\x20\";var ZFYm = \"tD2tl\".charAt(0);var oVcr = \"as\\x65\\x2c" ascii
    $s2 = "}}if (b){z = yPOr[(tnlYk) + (g) + (wqg) + (o) + (L) + (otsMF) + (O)]((Rnl) + (PeWJs)) + (X) + (ntpiQ) + (Wo) + (HK) + (Pw) + (cj" ascii
    $s3 = "z1) + (jkB) + (I0) + b ? (Vp) + (hq) + (BlW) : (wBWo) + (cPt) + (VuXG);}else{WScript.Echo((jjnZg) + (oVcr) + (ZFYm) + (Sct) + (I" ascii
    $s4 = "return A - oFQE;}var b = false;for (var fQhD = 0; fQhD < ECwu() * 1; fQhD++){" fullword ascii
    $s5 = "MPlUZ) + (vZ) + (kvk) + (k0) + (zMnTN) + (R) + (sgX), false);DVB[(A0) + (z0)]();while (DVB[(D) + (SGUC) + (q) + (v) + (NMMz)] < " ascii
    $s6 = "+ (KW) + (Ou) + (HcUa) + (MyIuK);};function Trl(){return (WLC) + (wi) + (tcSBc) + (geKLn);};function ECwu(){return 22;};function" ascii
    $s7 = " + (tcSBc) + (geKLn)]((m) + (XGnhZ) + (fR) + (abR));function RWjAs(dTSj){yPOr[(bkZfa)](dTSj, 0, 0);};function P(){return (zhxO) " ascii
    $s8 = "var sqgO = new this[(c)]();" fullword ascii
    $s9 = "b = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}