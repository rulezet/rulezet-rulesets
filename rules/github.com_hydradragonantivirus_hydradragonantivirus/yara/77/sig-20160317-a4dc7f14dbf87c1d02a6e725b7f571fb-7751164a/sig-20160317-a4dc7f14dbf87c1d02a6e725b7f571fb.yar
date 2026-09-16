rule sig_20160317_a4dc7f14dbf87c1d02a6e725b7f571fb {
  meta:
    description = "datamaliciousorder - file 20160317_a4dc7f14dbf87c1d02a6e725b7f571fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67a26aa779888a3f4f9dc255100fde4b7a3aed1cdd6a378d67b031ffc6855d1d"

  strings:
    $s1  = "var kjzo = \"!\";var jQMY = \"a\\x69n\";var FGpPb = \"ag\";var uTeU = \"nFhy n5zbS\".charAt(4);var Qc = \"\\x79\";var jhWZq = \"" ascii
    $s2  = "+ (naKNz);}else{WScript.Echo((cC) + (Ra) + (jhWZq) + (Qc) + (uTeU) + (FGpPb) + (jQMY) + (kjzo));}" fullword ascii
    $s3  = ")]();while (hZeD[(e0) + (F0) + (BN) + (hZv) + (giS) + (FWzBn) + (fjiTX)] < 4 ) {WScript[(BoRFq)](Dz() * 10)};hP = WScript[M()]((" ascii
    $s4  = "}}if (BDDKp){T = tZMh[(UGoiP) + (s) + (yZ) + (Vq) + (cp) + (TC) + (yT) + (eM) + (Z)]((gbk) + (f) + (h) + (cCK)) + (NiUMt) + (NZN" ascii
    $s5  = "return x - GALyt;}var BDDKp = false;for (var ZKh = 0; ZKh < Dz() * 1; ZKh++){" fullword ascii
    $s6  = "V)]((gDnaW) + (hw) + (rDHa) + (T0) + (PBy));function m(meK){tZMh[(Ev)](meK, 0, 0);};function VCUDV(){return (XZ) + (AGP) + (ithP" ascii
    $s7  = "A) + (F);};function M(){return (Dyq) + (Aki) + (OEYz) + (ubCIn) + (NmMV);};function Dz(){return 22;};function ddgD(){" fullword ascii
    $s8  = ") + (Fox) + (RJj) + (y) + (bCs) + (CKuZ) + (ZYTWI) + (oemPr) + (yNeU) + (Ock) + (Kcdv) + (U) + (Acf) + (DMFsM), false);hZeD[(sgG" ascii
    $s9  = "BDDKp = true;" fullword ascii
    $s10 = "var IIsEM = new this[(lpNap)]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}