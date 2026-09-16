rule sig_20160405_9c0f72c825932e02fb41591a7c3a115c {
  meta:
    description = "datamaliciousorder - file 20160405_9c0f72c825932e02fb41591a7c3a115c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "645e0f965161c9a7d589dfd09a234fb506403a19da6bc92339a5c03168b95896"

  strings:
    $s1  = "var PVt = (\"2.XMLHTTP QsrirCU Prtof XML ream St YUelCFwV AD hurmrVy O XEiX D\").split(\" \");" fullword ascii
    $s2  = "var DL = true  , JMyR = PVt[7] + PVt[9] + PVt[11];" fullword ascii
    $s3  = "return toHwwUS[0] + toHwwUS[2] + toHwwUS[4] + \".F\" + toHwwUS[7] + toHwwUS[9] + toHwwUS[12] + toHwwUS[14];" fullword ascii
    $s4  = "ioVw.open(FWToe,xTJub,false);" fullword ascii
    $s5  = "function bfAnmVD(MAEc,KZRlC) {" fullword ascii
    $s6  = "function CrbhJi(vkZAXoI) {" fullword ascii
    $s7  = "function yWlnltsa(bzv) {" fullword ascii
    $s8  = "return khcq;" fullword ascii
    $s9  = "return zVa.split(DafbE);" fullword ascii
    $s10 = "FjL = n; break; " fullword ascii
    $s11 = "return \"iklaXfvELZFKEn\";" fullword ascii
    $s12 = "function FEiZ(coIHV) {" fullword ascii
    $s13 = "function gTkD(QyHhM) {" fullword ascii
    $s14 = "if(n>=B.length) {break;}" fullword ascii
    $s15 = "return FHoBL;" fullword ascii
    $s16 = "function zhbaeso(kamP) {" fullword ascii
    $s17 = "function ZgRDKXUy(xecr) {" fullword ascii
    $s18 = "function Eitjdr(CXXP,CEArLK) {" fullword ascii
    $s19 = "var NXzNkza = \"laVKrj*Hgi*pt.S\"+\"hell*LXnRDDP*Scri*\";" fullword ascii
    $s20 = "function FHKMw(zVa,DafbE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}