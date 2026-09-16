rule sig_20160303_c8ebef9be0fe5eb05a820ab8f6e20287 {
  meta:
    description = "datamaliciousorder - file 20160303_c8ebef9be0fe5eb05a820ab8f6e20287.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "757218f9ff14e76587d02a1637f509be9fc2c0155766eb886371fc129ded7faf"

  strings:
    $s1  = "var GZ = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(AXHuH);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + FWkwNOm + \".F\" + cpviQmfYRO + mPoQj + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var tNA = (Hfa + \"TTP\" + \" ScSHeHL xsXZG XML ream St VLlLafTi AD sliTjmH OD\").split(\" \");" fullword ascii
    $s5  = "var JL = true  , kDPP = tNA[7] + \"\" + tNA[9];" fullword ascii
    $s6  = "eonTr.open(acIwe,ytxiK,false);" fullword ascii
    $s7  = "function tKxN(AXHuH) {" fullword ascii
    $s8  = "function GDgB(fKnMv,QEnwx) {" fullword ascii
    $s9  = "function vpbQ(GVKLW) {" fullword ascii
    $s10 = "function BBiQoPDHB(GnwGoVQEVrB) {" fullword ascii
    $s11 = "if (fQFQb == 447-247){return true;} else {return false;}" fullword ascii
    $s12 = "function FmFD(eonTr,ytxiK,acIwe) {" fullword ascii
    $s13 = "if(f>=Q.length) {break;}" fullword ascii
    $s14 = "if (jDBhx > 198856-454){return true;} else {return false;}" fullword ascii
    $s15 = "function uLRR(DuVWK) {" fullword ascii
    $s16 = "function IZHks(VVqnyK) {" fullword ascii
    $s17 = "function klNb(fQFQb) {" fullword ascii
    $s18 = "sZd = f; break; " fullword ascii
    $s19 = "return ncLzK.status;" fullword ascii
    $s20 = "function GdfjTGRLp(aKbME,CwlQC,LKrhL) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}