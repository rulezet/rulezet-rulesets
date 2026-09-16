rule sig_20160317_cef3fe7ed9676b4ff1bc5e1899f10213 {
  meta:
    description = "datamaliciousorder - file 20160317_cef3fe7ed9676b4ff1bc5e1899f10213.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fe9b6b7fc6bcd91f9549ae9f21c0060b022fad8225f8d85150e73a4bc094a4e"

  strings:
    $s1  = "var MyII = \"1G!0VcR7\".charAt(2);var pVKZL = \"nx2SN7\".charAt(0);var lrwtW = \"gai\";var hWEc = \"\\x72y\\x20a\";var uAI = \"," ascii
    $s2  = "}}if (sMt){O = HheU[(iKpX) + (How) + (yFWZL) + (kSkoO) + (wJdql) + (cL) + (V) + (ZXCbo)]((rZImG) + (RB) + (fK)) + (qm) + (IVvGh)" ascii
    $s3  = ";while (rH[(AVogz) + (h1) + (RZE) + (ZEk) + (fSbE) + (odZw)] < 4 ) {WScript[(ihs) + (hLD)](SLTzh() * 10)};Ho = WScript[kt()]((ee" ascii
    $s4  = "c) + (F) + (JaJBf) + (sAGE) + (oOOri) + (Em) + (vP) + sMt ? (xt) + (dKyYB) + (oG) + (aRn) : (A) + (fu) + (epXOL);}else{WScript.E" ascii
    $s5  = "return OBX - vql;}var sMt = false;for (var s = 0; s < SLTzh() * 1; s++){" fullword ascii
    $s6  = "as\";var dKyYB = \"d\";var xt = \"as\";var vP = \"isdf\";var Em = \"\\x79auh\";var oOOri = \"GxfuBfHm\".charAt(5);var sAGE = \"g" ascii
    $s7  = "E) + (QMX) + (WJtp) + (wN) + (CDPL) + (uRJnm) + (AoRH) + (bdCjT) + (hehAh) + (Wly) + (qhuRj) + (tDag) + (SD), false);rH[(lvD)]()" ascii
    $s8  = "o) + (zgZrG);};function kt(){return (h) + (VeiEI) + (p);};function SLTzh(){return 22;};function lHm(){" fullword ascii
    $s9  = "var ihKBb = new this[(MAOsr)]();" fullword ascii
    $s10 = " + (VeiEI) + (p)]((er) + (Lj) + (ZV) + (VKqeb));function W(tQH){HheU[(h0)](tQH, 0, 0);};function w(){return (caR) + (qkPIU) + (T" ascii
    $s11 = "sMt = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}