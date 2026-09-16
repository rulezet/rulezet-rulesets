rule sig_20160305_cc4f8c666e12388d8d182dd1f5dd835d {
  meta:
    description = "datamaliciousorder - file 20160305_cc4f8c666e12388d8d182dd1f5dd835d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36a5ea884c6df3a8e81205b2d1dbe1fa7842d210a17bc47b688232edb46a5708"

  strings:
    $s1  = "var XnTey = \"ozbnMZ ZVh pt.Shell vCpZDhi Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var Upa = (JyG + \"TTP\" + \" YxkXDIA xsrRa XML ream St ieGbxKmH AD uSXSnkJ OD\").split(\" \");" fullword ascii
    $s3  = "var go = true  , LubH = Upa[7] + \"\" + Upa[9];" fullword ascii
    $s4  = "return ChAkPhv[0] + ChAkPhv[2] + ChAkPhv[4] + \".F\" + ChAkPhv[7] + ChAkPhv[9] + ChAkPhv[12] + ChAkPhv[14];" fullword ascii
    $s5  = "var ChAkPhv = \"Sc MhIGoJe r GAQciVmvw ipting yjLsdxu XBr ile VdKLJLrnMxyJRN System Sk oimrR Obj YZHzcS ect XLivQDD\".split(\" " ascii
    $s6  = "AqnTr.open(pCycv,MGImv,false);" fullword ascii
    $s7  = "function XalfMdnaR(oyjVZRWNzHL) {" fullword ascii
    $s8  = "function QKlY(JxQbG) {" fullword ascii
    $s9  = "if (aSKrG == 1137-937){return true;} else {return false;}" fullword ascii
    $s10 = "if (XQUEs > 170720-477){return true;} else {return false;}" fullword ascii
    $s11 = "function VsLU(nZylf) {" fullword ascii
    $s12 = "function wCONXTDSj(yFjfd,lITlf,HVLps) {" fullword ascii
    $s13 = "function gfzD(AqnTr,MGImv,pCycv) {" fullword ascii
    $s14 = "return Asjjyek" fullword ascii
    $s15 = "return MHxmI.status;" fullword ascii
    $s16 = "function ivSYH(WUZKbU) {" fullword ascii
    $s17 = "function GsOTFMI(vOas) {" fullword ascii
    $s18 = "sgH = D; break; " fullword ascii
    $s19 = "function QVxc(yxnuE) {" fullword ascii
    $s20 = "function lPuQ(MHxmI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}