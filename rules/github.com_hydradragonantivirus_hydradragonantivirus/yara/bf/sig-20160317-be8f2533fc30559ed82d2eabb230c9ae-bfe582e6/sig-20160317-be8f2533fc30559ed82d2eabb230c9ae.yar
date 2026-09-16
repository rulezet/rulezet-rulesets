rule sig_20160317_be8f2533fc30559ed82d2eabb230c9ae {
  meta:
    description = "datamaliciousorder - file 20160317_be8f2533fc30559ed82d2eabb230c9ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01cc8658dfe0da26ceededd034e2d8dfc4d96cb1712a6fdc9f86a516896576a"

  strings:
    $x1  = "var hSqU = \"\\x67\\x61in\\x21\";var rjmK = \"ry a\";var y = \", \\x74\";var CsrcF = \"FiN4IeD\".charAt(5);var uUjVr = \"Pl\\x65" ascii
    $s2  = "EE = \"rwC\".charAt(2);OLoX = WScript[(EE) + (ehnc) + (G) + (tsD)]((EV) + (Ob) + (aN) + (mAtM));function V(ywhSP){OLoX[(e) + (Sf" ascii
    $s3  = "(FvKqi) : (U) + (DNM) + (L0) + (CSHk);}else{WScript.Echo((uUjVr) + (CsrcF) + (y) + (rjmK) + (hSqU));}" fullword ascii
    $s4  = "}}if (Uep){kh = OLoX[(diSb) + (Cxa) + (nT) + (ngC) + (nMNY) + (rVVy) + (aQv) + (jneV)]((c0) + (RLehm) + (UfB) + (vv)) + (Cx) + (" ascii
    $s5  = " + (Pq) + (ZyqC) + (mwpfb) + (rGvy), false);Y[(D) + (Cwk)]();while (Y[(t0) + (DiDy) + (B) + (Z) + (Y0)] < 4 ) {WScript[(VsmD)](J" ascii
    $s6  = "return zEu - UKSY;}var Uep = false;for (var aigJ = 0; aigJ < Jb() * 1; aigJ++){" fullword ascii
    $s7  = "var rim = new this[(eJIrC)]();" fullword ascii
    $s8  = ")](ywhSP, 0, 0);};function j(){return (YAJa) + (WwDm) + (qqN) + (X) + (N);};function no(){return (EE) + (ehnc) + (G) + (tsD);};f" ascii
    $s9  = "unction Jb(){return 22;};function fNws(){" fullword ascii
    $s10 = "Uep = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}