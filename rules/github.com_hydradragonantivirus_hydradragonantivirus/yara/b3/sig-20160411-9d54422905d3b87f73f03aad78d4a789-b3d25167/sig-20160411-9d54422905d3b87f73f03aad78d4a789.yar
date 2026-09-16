rule sig_20160411_9d54422905d3b87f73f03aad78d4a789 {
  meta:
    description = "datamaliciousorder - file 20160411_9d54422905d3b87f73f03aad78d4a789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb50d65800a0cf7240f70bf57aa87509e252189e7247444e419a4f09681b585c"

  strings:
    $s1  = "var MZ = true  , MLwX = fgL[7] + fgL[9] + fgL[11];" fullword ascii
    $s2  = "return grNORQD[0] + grNORQD[2] + grNORQD[4] + \".F\" + grNORQD[7] + grNORQD[9] + grNORQD[12] + grNORQD[14];" fullword ascii
    $s3  = "NEuH.open(aPhqE,zdBcc,false);" fullword ascii
    $s4  = "var fgL = (\"2.XMLHTTP gvANLns FSveP XML ream St btetTekf AD ObUEyJK O DuDC D\").split(\" \");" fullword ascii
    $s5  = "if(b>=u.length) {break;}" fullword ascii
    $s6  = "function pYGly(XseUKw) {" fullword ascii
    $s7  = "return lxUPV;" fullword ascii
    $s8  = "return fdP.size;" fullword ascii
    $s9  = "if (GWdIh > 153128-932){return true;} else {return false;}" fullword ascii
    $s10 = "return SHZKl.status;" fullword ascii
    $s11 = "return new ActiveXObject(HyiB);" fullword ascii
    $s12 = "Imt = b; break; " fullword ascii
    $s13 = "function FqQxLp(hXBrpXL) {" fullword ascii
    $s14 = "return \"GksSsJhZwJUXyh\";" fullword ascii
    $s15 = "function vQNGapx(vtff) {" fullword ascii
    $s16 = "function fElB(VNnUf,UzRTh) {" fullword ascii
    $s17 = "return vtff[xDHOTMg[0]+xDHOTMg[1]];" fullword ascii
    $s18 = "function hNUN(sJInc) {" fullword ascii
    $s19 = "function rzCxilIE(fdP) {" fullword ascii
    $s20 = "return KVv[vZxr[0]](hPkNH);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}