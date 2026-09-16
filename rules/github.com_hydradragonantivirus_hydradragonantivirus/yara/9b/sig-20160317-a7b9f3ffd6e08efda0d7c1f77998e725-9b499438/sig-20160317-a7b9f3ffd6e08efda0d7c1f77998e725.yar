rule sig_20160317_a7b9f3ffd6e08efda0d7c1f77998e725 {
  meta:
    description = "datamaliciousorder - file 20160317_a7b9f3ffd6e08efda0d7c1f77998e725.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f0a775479e5afa9f140fc3e9c4c1b036ad4815e55d99fbc6ab931aefe1b02ad"

  strings:
    $s1  = "var G0 = \"gain!\";var q0 = \" \\x61\";var jSDl = \"\\x74ry\";var Y = \"a\\x73e, \";var U = \"\\x6ce\";var YQgO = \"P\";var ERxe" ascii
    $s2  = " (dW) + (rNOH) + (blv) + (gRJj) + jg ? (AZIc) + (wDTU) + (YPoO) + (RFiFp) : (lVPET) + (ERxev);}else{WScript.Echo((YQgO) + (U) + " ascii
    $s3  = "}}if (jg){v = OCVpo[(Ro) + (WJ) + (EBpju) + (QVvbS) + (VY) + (abF) + (AxmRL) + (Q)]((ElI) + (j) + (HSQK)) + (Ddq) + (ysCC) + (tV" ascii
    $s4  = "return LEI - x;}var jg = false;for (var hEdt = 0; hEdt < xVWct() * 1; hEdt++){" fullword ascii
    $s5  = "{return (tis) + (p) + (doG) + (AtYza) + (Nu);};function TvJ(){return (dO) + (kFIS) + (zVnGJ) + (AzAOj);};function xVWct(){return" ascii
    $s6  = " + (kFIS) + (zVnGJ) + (AzAOj)]((rvUsI) + (GWe) + (PXzks) + (zer) + (tSrep));function f(oyF){OCVpo[(u)](oyF, 0, 0);};function V()" ascii
    $s7  = "fWLy) + (dHgak) + (lLIN) + (a) + (GGL) + (xuQ) + (c) + (phGfj) + (LIy) + (G) + (QNjNV), false);r[(RpaYC)]();while (r[(u0) + (ZS)" ascii
    $s8  = "var F = new this[(mOyr) + (YI) + (jmiFs)]();" fullword ascii
    $s9  = "var G0 = \"gain!\";var q0 = \" \\x61\";var jSDl = \"\\x74ry\";var Y = \"a\\x73e, \";var U = \"\\x6ce\";var YQgO = \"P\";var ERxe" ascii
    $s10 = " 22;};function h(){" fullword ascii
    $s11 = "jg = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}