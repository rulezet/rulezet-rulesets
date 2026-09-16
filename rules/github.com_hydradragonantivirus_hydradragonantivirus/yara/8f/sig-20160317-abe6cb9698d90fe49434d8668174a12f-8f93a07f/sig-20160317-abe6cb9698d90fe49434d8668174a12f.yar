rule sig_20160317_abe6cb9698d90fe49434d8668174a12f {
  meta:
    description = "datamaliciousorder - file 20160317_abe6cb9698d90fe49434d8668174a12f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f2c2be3e6e75c66f66e3d1703d41ae421c3e9a3cf9f45361dd5dc8164c8bf75"

  strings:
    $s1 = "var L0 = \"!\";var f = \"n\";var cZY = \"g\\x61\\x69\";var YkiK = \"ry \\x61\";var fg = \" t\";var V = \"ase,\";var eDGCt = \"" ascii
    $s2 = "N) + ba ? (cK) + (TuVN) + (m) + (Hj) : (UvcL) + (DGR) + (e) + (PeT);}else{WScript.Echo((F) + (eDGCt) + (V) + (fg) + (YkiK) + (cZ" ascii
    $s3 = "}}if (ba){oj = S[(fuJ) + (Dy) + (vmD) + (EQbT) + (y0) + (HdMjZ) + (d) + (Wtqc) + (wEZTo)]((dM) + (FkDVJ)) + (RXGuo) + (RsUH) + (" ascii
    $s4 = "return Sfr - KtlLJ;}var ba = false;for (var JO = 0; JO < l() * 1; JO++){" fullword ascii
    $s5 = "w(){return (TeVp) + (t) + (PQt) + (Skr);};function l(){return 22;};function NJQE(){" fullword ascii
    $s6 = " + (O) + (eAvQ));function SLWmf(QPC){S[(L)](QPC, 0, 0);};function bJf(){return (vwG) + (ahWv) + (CEteh) + (NY) + (c);};function " ascii
    $s7 = " (cXwOi) + (niyZ) + (RTu) + (pM) + (CJ) + (sBx) + (O1) + (PGuf), false);bdnox[(n0)]();while (bdnox[(DAv) + (muYi) + (B) + (St)] " ascii
    $s8 = "var qFoz = new this[(IzZFw) + (fLQ)]();" fullword ascii
    $s9 = "ba = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}