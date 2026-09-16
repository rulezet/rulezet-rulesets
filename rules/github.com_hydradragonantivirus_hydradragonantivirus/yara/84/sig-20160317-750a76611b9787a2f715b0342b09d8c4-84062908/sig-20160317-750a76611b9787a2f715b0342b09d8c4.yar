rule sig_20160317_750a76611b9787a2f715b0342b09d8c4 {
  meta:
    description = "datamaliciousorder - file 20160317_750a76611b9787a2f715b0342b09d8c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07ebcc570883016edca214c200759e17b8f4d931185390752fe09ad1c4b6d360"

  strings:
    $s1  = "var RPDE = \"!\";var YEmDL = \"ain\";var cicp = \"r\\x79\\x20\\x61\\x67\";var zM = \"e,\\x20t\";var lvtc = \"s\";var b = \"\\x65" ascii
    $s2  = "}}if (upb){F = MkNA[(d) + (XdV) + (tpc) + (Lhv) + (UsBI) + (vizh) + (D) + (S)]((MwOP) + (cO) + (Oh)) + (WFuvR) + (o0) + (WQt) + " ascii
    $s3  = " = \"r\\x65a\";var PBvF = \"\\x43\";MkNA = WScript[(PBvF) + (fh) + (QMGz) + (BNXcw) + (qElke)]((rV) + (HHN) + (xPck) + (lVo));fu" ascii
    $s4  = "pb ? (IsL) + (M) + (nn) : (UWDok) + (VsOx);}else{WScript.Echo((oGu) + (b) + (lvtc) + (zM) + (cicp) + (YEmDL) + (RPDE));}" fullword ascii
    $s5  = "return xkhSx - Ik;}var upb = false;for (var XId = 0; XId < Utkm() * 1; XId++){" fullword ascii
    $s6  = " + (cEkhJ) + (onM) + (f) + (EAjz) + (cFuhN) + (iW) + (Zx) + (GbUP) + (Vt) + (fwyKC), false);l[(DybpK) + (uLNLs) + (D0)]();while " ascii
    $s7  = " gHNrJ(Ax){MkNA[(KkzV) + (Ll)](Ax, 0, 0);};function URHBv(){return (tXfx) + (ZNR) + (yX) + (L) + (SReb);};function Fn(){return (" ascii
    $s8  = "PBvF) + (fh) + (QMGz) + (BNXcw) + (qElke);};function Utkm(){return 22;};function hGyk(){" fullword ascii
    $s9  = "var q = new this[(JDTj) + (V)]();" fullword ascii
    $s10 = "upb = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}