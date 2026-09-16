rule sig_20160310_abf7524e6cc4592bc6b63cdb521c8359 {
  meta:
    description = "datamaliciousorder - file 20160310_abf7524e6cc4592bc6b63cdb521c8359.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eda162db60861cd6af0c3a3bc7730e6f8e585c8f94825485b1945d4cc5f2602"

  strings:
    $s1  = "return PhndDSN[0] + PhndDSN[2] + PhndDSN[4] + \".F\" + PhndDSN[7] + PhndDSN[9] + PhndDSN[12] + PhndDSN[14];" fullword ascii
    $s2  = "var Zq = true  , jqWW = iFh[7] + iFh[9] + iFh[11];" fullword ascii
    $s3  = "var iFh = (\"2.XMLHTTP LjICJaS paBmS XML ream St NsjMQowb AD HnFPKjF O bzaX D\").split(\" \");" fullword ascii
    $s4  = "var PhndDSN = \"Sc GqOMofv r sTqzoYokI ipting yUlIaQX NuQ ile PeNJhLXpNntYFa System sH FAcml Obj UNSMla ect JWLaFUr\".split(\" " ascii
    $s5  = "swmZW.open(GuxUk,icPkW,false);" fullword ascii
    $s6  = "if (v >= FaPBw.length) {break;}" fullword ascii
    $s7  = "if (YjkWT > 159839-994){return true;} else {return false;}" fullword ascii
    $s8  = "return new ActiveXObject(ySTJSD);" fullword ascii
    $s9  = "function VlFn(unzqa,zBfFR) {" fullword ascii
    $s10 = "function EeVk(swmZW,icPkW,GuxUk) {" fullword ascii
    $s11 = "function aWVBfwH(UNZt,PHExX) {" fullword ascii
    $s12 = "function fNVfedlye(nXLbhxUkyhf) {" fullword ascii
    $s13 = "ftC = k; break; " fullword ascii
    $s14 = "return UNZt.ExpandEnvironmentStrings(PHExX);" fullword ascii
    $s15 = "return YMlz.responseBody;" fullword ascii
    $s16 = "if(k>=o.length) {break;}" fullword ascii
    $s17 = "return aWVBfwH(yI,OuFMx[133-127]+OuFMx[674-667]+OuFMx[535-527]);" fullword ascii
    $s18 = "function sjdo(CjZDK) {" fullword ascii
    $s19 = "function JWWL(ibiiH) {" fullword ascii
    $s20 = "return FVtQsy.position=869-869;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}