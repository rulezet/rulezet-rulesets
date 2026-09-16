rule sig_20160419_b3a1941fc1a9cc7148410918f69e8f3f {
  meta:
    description = "datamaliciousorder - file 20160419_b3a1941fc1a9cc7148410918f69e8f3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2619d031f36d285158cecbae4d5dcd3cb30da08ec78049eaa6d29373efecb536"

  strings:
    $s1  = "return XmxVDSM[0] + XmxVDSM[2] + XmxVDSM[4] + \".F\" + XmxVDSM[7] + XmxVDSM[9] + XmxVDSM[12] + XmxVDSM[14];" fullword ascii
    $s2  = "var ei = true  , ndqS = iav[7] + iav[9] + iav[11];" fullword ascii
    $s3  = "XOIu.open(xpkNS,JdQFi,false);" fullword ascii
    $s4  = "var iav = (\"2.XMLHTTP HgQGxid PidKY XML ream St JRBhWZlZ AD OpZDWYO O qkiW D\").split(\" \");" fullword ascii
    $s5  = "if(E>=N.length) {break;}" fullword ascii
    $s6  = "function yYcF(mTTtk) {" fullword ascii
    $s7  = "function NvuoAyq(Ybnm,cIxFD) {" fullword ascii
    $s8  = "function xBOd(TDHNk) {" fullword ascii
    $s9  = "return LUUFYTU[0];" fullword ascii
    $s10 = "return UYW[HNEs[0]](EjuqU);" fullword ascii
    $s11 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s12 = "return HIbp[cflZXHr[0]+cflZXHr[1]];" fullword ascii
    $s13 = "return TDHNk.status;" fullword ascii
    $s14 = "function wyfo(qAuUe,FABAo) {" fullword ascii
    $s15 = "return wwjLl;" fullword ascii
    $s16 = "if (WwMbR != 1128-928){return false;} else {return true;}" fullword ascii
    $s17 = "function rPtfaahb(abi) {" fullword ascii
    $s18 = "function Ahhz(UzBFg) {" fullword ascii
    $s19 = "Tyz = E; break; " fullword ascii
    $s20 = "function dnWEQft(HIbp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}