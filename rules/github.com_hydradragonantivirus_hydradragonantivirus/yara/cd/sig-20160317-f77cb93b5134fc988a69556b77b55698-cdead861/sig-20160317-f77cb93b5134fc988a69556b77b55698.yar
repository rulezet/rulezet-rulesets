rule sig_20160317_f77cb93b5134fc988a69556b77b55698 {
  meta:
    description = "datamaliciousorder - file 20160317_f77cb93b5134fc988a69556b77b55698.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ab723318567ec27f298bbe83872259c42a84908feb6bf9de62e058d5f2946b8"

  strings:
    $s1 = "var Aqs = \"gai\\x6e!\";var FYxV = \"Nouca\".charAt(4);var HFK = \"y \";var dzhP = \"r\";var CnST = \"e\\x2c \\x74\";var JSZOM =" ascii
    $s2 = "+ (Ph) + (l1) + (WFJk) + (l2) + (FOop) + (p) + (bkmX), false);M[(HVqo) + (zF)]();while (M[(iU) + (T) + (WM)] < 4 ) {WScript[(xdC" ascii
    $s3 = "GGi) + (rdINk) : (cNXYU) + (btEj) + (nnMlM) + (nslvq);}else{WScript.Echo((dJ) + (OJbU) + (JSZOM) + (CnST) + (dzhP) + (HFK) + (FY" ascii
    $s4 = "}}if (YiHd){jC = fCah[(I0) + (qUex) + (l) + (rA) + (FPTsa) + (IM) + (ZcjC)]((zLW) + (Jp)) + (DphKU) + (Gse) + (KDM) + (SCY) + (k" ascii
    $s5 = "return XBgv - F;}var YiHd = false;for (var H = 0; H < Wts() * 1; H++){" fullword ascii
    $s6 = "){return (hBMJ) + (xmCXu) + (Ju) + (vldO);};function BeTB(){return (Kl) + (Y) + (XMgE) + (n);};function Wts(){return 22;};functi" ascii
    $s7 = "YiHd = true;" fullword ascii
    $s8 = "var QVvGk = new this[(VD)]();" fullword ascii
    $s9 = "Kl) + (Y) + (XMgE) + (n)]((yBH) + (d) + (Yab) + (Fo) + (dJu) + (k0));function I(xdTAP){fCah[(NK)](xdTAP, 0, 0);};function XLRtR(" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}