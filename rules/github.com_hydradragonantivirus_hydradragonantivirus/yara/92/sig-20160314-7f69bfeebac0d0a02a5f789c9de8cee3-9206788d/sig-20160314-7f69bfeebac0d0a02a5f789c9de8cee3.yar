rule sig_20160314_7f69bfeebac0d0a02a5f789c9de8cee3 {
  meta:
    description = "datamaliciousorder - file 20160314_7f69bfeebac0d0a02a5f789c9de8cee3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e791b204833863028f068d474ddea9b883a9195b266bfacb9259049eb29cf08"

  strings:
    $s1  = "var zT = true  , Hdyq = Gwl[7] + Gwl[9] + Gwl[11];" fullword ascii
    $s2  = "return kCsWjiF[0] + kCsWjiF[2] + kCsWjiF[4] + \".F\" + kCsWjiF[7] + kCsWjiF[9] + kCsWjiF[12] + kCsWjiF[14];" fullword ascii
    $s3  = "fBVqF.open(Nezoo,oUVsW,false);" fullword ascii
    $s4  = "var Gwl = (\"2.XMLHTTP rJvSAxQ mthJQ XML ream St PzTKNUvn AD slHrUlP O aguO D\").split(\" \");" fullword ascii
    $s5  = "if(N>=T.length) {break;}" fullword ascii
    $s6  = "function ktqC(kqRQu) {" fullword ascii
    $s7  = "return nZqXcJ.position=411-411;" fullword ascii
    $s8  = "bWb = N; break; " fullword ascii
    $s9  = "return XOy.size;" fullword ascii
    $s10 = "return YZLzXTG" fullword ascii
    $s11 = "return zNyjN.status;" fullword ascii
    $s12 = "if (F >= kxDsa.length) {break;}" fullword ascii
    $s13 = "function SQYB(VInLC) {" fullword ascii
    $s14 = "if (iZsEO > 151717-874){return true;} else {return false;}" fullword ascii
    $s15 = "function XGuTqft(FIco) {" fullword ascii
    $s16 = "function fKmB(EgERZ) {" fullword ascii
    $s17 = "function PoEI(iZsEO) {" fullword ascii
    $s18 = "return LyzuabB(mV,UrJWM[132-126]+UrJWM[127-120]+UrJWM[394-386]);" fullword ascii
    $s19 = "function SxnD(zNyjN) {" fullword ascii
    $s20 = "if (VInLC == 642-442){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}