rule sig_20160318_b840268da33df1d81c2f0b45c0cdcec9 {
  meta:
    description = "datamaliciousorder - file 20160318_b840268da33df1d81c2f0b45c0cdcec9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eabcbdd0ce54f873d8bca68182ce93a6837f702af54260eeef0ecd44e8c4abd"

  strings:
    $s1  = "var j0 = \"g\\x61in!\";var e0 = \"ry a\";var no = \" t\";var H1 = \"e,\";var YmlR = \"eas\";var mLuiE = \"P\\x6c\";var IVhf = \"" ascii
    $s2  = "sA = WScript[(KuO) + (hrP) + (bY) + (hQ)]((uBsv) + (QYZor) + (LQ) + (DI) + (bWUYg));function fFVuo(GZ){YSzsA[(ph)](GZ, 0, 0);};f" ascii
    $s3  = " (UhWe) + (sjz) + (e) + (VD) + (ZQhj) + (kQCP) + (Ht) + H ? (qd) + (n1) : (GDj) + (IVhf);}else{WScript.Echo((mLuiE) + (YmlR) + (" ascii
    $s4  = " (WqHC) + (CtDxJ) + (GTQcF) + (R), false);otnAs[(d) + (ywME)]();while (otnAs[(RjwvM) + (StIE) + (cmf)] < 4 ) {WScript[(xC) + (wo" ascii
    $s5  = "}}if (H){WR = YSzsA[(o) + (CfR) + (F) + (X) + (Cuq) + (Dx) + (IhDS)]((rx) + (XsK)) + (QasNc) + (W) + (GLxe) + (n0) + (ooKDL) + (" ascii
    $s6  = "return OMRRY - xjuzj;}var H = false;for (var EGky = 0; EGky < zg() * 1; EGky++){" fullword ascii
    $s7  = "unction oAx(){return (k) + (Yo) + (QYdaw) + (jARew);};function GP(){return (KuO) + (hrP) + (bY) + (hQ);};function zg(){return 22" ascii
    $s8  = "var abRXA = new this[(eEAI) + (XfNM) + (oRw)]();" fullword ascii
    $s9  = ";};function n(){" fullword ascii
    $s10 = "H = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}