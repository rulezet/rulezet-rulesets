rule sig_20160301_da4734f532d9d30de2890c1ff4422935 {
  meta:
    description = "datamaliciousorder - file 20160301_da4734f532d9d30de2890c1ff4422935.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec1972bebd93f3761fcd5d3d1d2c39882447fae7be8d6bbd00d5ce13a0df631"

  strings:
    $s1  = "var xJ = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(PtovX);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + ECysWfm + \".F\" + qPmLbRZnzh + WCFUP + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var Pz = true  , XTRy = vfn[7] + \"\" + vfn[9];" fullword ascii
    $s5  = "var vfn = (djo + \"TTP\" + \" MGrcUms LAdEf XML ream St JaStlvCY AD SqhHRXR OD\").split(\" \");" fullword ascii
    $s6  = "function aqgcoMMH() {" fullword ascii
    $s7  = "QMlAu.open(IxpbL,rPZNE,false);" fullword ascii
    $s8  = "function KpLv(aPzub,aUNfg) {" fullword ascii
    $s9  = "function gnJf(PtovX) {" fullword ascii
    $s10 = "function YRVL(QMlAu,rPZNE,IxpbL) {" fullword ascii
    $s11 = "if (ILqed == 540-340){return true;} else {return false;}" fullword ascii
    $s12 = "function zJoU(IAtMO,FKXlb) {" fullword ascii
    $s13 = "function ZSZU(whyUt) {" fullword ascii
    $s14 = "function qRaXe(jRbtlF) {" fullword ascii
    $s15 = "if(k>=j.length) {break;}" fullword ascii
    $s16 = "VAE = k; break; " fullword ascii
    $s17 = "return XJuTW;" fullword ascii
    $s18 = "function VxUf(eZhZq) {" fullword ascii
    $s19 = "function weRQ(ILqed) {" fullword ascii
    $s20 = "function sGdNQjoAv(bZGdGgeotMh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}