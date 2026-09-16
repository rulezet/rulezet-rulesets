rule sig_20160405_dbcf8f06e460279de6b62707519f7d6e {
  meta:
    description = "datamaliciousorder - file 20160405_dbcf8f06e460279de6b62707519f7d6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d1d8ab0c5f2bb639e45c2ed6c1b7346d3a4a3dec2b42a0e3e81a548d61921c5"

  strings:
    $s1  = "var QL = true  , nneO = bjq[7] + bjq[9] + bjq[11];" fullword ascii
    $s2  = "return fvKgBmk[0] + fvKgBmk[2] + fvKgBmk[4] + \".F\" + fvKgBmk[7] + fvKgBmk[9] + fvKgBmk[12] + fvKgBmk[14];" fullword ascii
    $s3  = "uNWW.open(rnVRm,HRBeY,false);" fullword ascii
    $s4  = "var bjq = (\"2.XMLHTTP VAmYGEv cgqZk XML ream St sQIahcmP AD yYXOSQe O ofDc D\").split(\" \");" fullword ascii
    $s5  = "if(M>=O.length) {break;}" fullword ascii
    $s6  = "function yRqBh(ozYGHrcc,UOpJ) {" fullword ascii
    $s7  = "function NLUjv(lpj,ZVjMe) {" fullword ascii
    $s8  = "return ECmxJ.status;" fullword ascii
    $s9  = "return FmEr[tWtWec[0]];" fullword ascii
    $s10 = "return FsMqZAL[0];" fullword ascii
    $s11 = "function VAHrYkzRz(mRNIYeVIhVf) {" fullword ascii
    $s12 = "return PgqvOhf;" fullword ascii
    $s13 = "function miQEupw(FmEr) {" fullword ascii
    $s14 = "return xcpiQsv(fS,beFLH[573-567]+beFLH[331-324]+beFLH[269-261]);" fullword ascii
    $s15 = "if (ABzGy == 825-625){return true;} else {return false;}" fullword ascii
    $s16 = "function iJExI(lEhJAM) {" fullword ascii
    $s17 = "function fCYEpvbRw(fDzZJ) {" fullword ascii
    $s18 = "function cSxbBQAE(iRI) {" fullword ascii
    $s19 = "function paIh(ECmxJ) {" fullword ascii
    $s20 = "return iRI.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}