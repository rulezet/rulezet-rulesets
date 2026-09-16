rule sig_20160324_a4374226a3736b4cbb36c83c9c4c4fcb {
  meta:
    description = "datamaliciousorder - file 20160324_a4374226a3736b4cbb36c83c9c4c4fcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7d4e07808e2ee1a3e5228704ba285faf6bae09a26a15c8f041f96233a01f434"

  strings:
    $s1  = "return WScript.CreateObject(tFuQW);" fullword ascii
    $s2  = "return GzGjzoo[0] + GzGjzoo[2] + GzGjzoo[4] + \".F\" + GzGjzoo[7] + GzGjzoo[9] + GzGjzoo[12] + GzGjzoo[14];" fullword ascii
    $s3  = "var cs = true  , HVVp = OYg[7] + OYg[9] + OYg[11];" fullword ascii
    $s4  = "AIGS.open(ICyDc,atsFA,false);" fullword ascii
    $s5  = "var OYg = (\"2.XMLHTTP LzPFGTT vwicn XML ream St REdHeitN AD ZtgfdeS O eqwx D\").split(\" \");" fullword ascii
    $s6  = "if(q>=o.length) {break;}" fullword ascii
    $s7  = "var bxHJbRR = \"ArYgdM*uDK*pt.S\"+\"hell*wrFuNcU*Scri*\";" fullword ascii
    $s8  = "function rZNktzeDr(PxjZA) {" fullword ascii
    $s9  = "if (FJbcX > 179452-508){return true;} else {return false;}" fullword ascii
    $s10 = "if (Q >= GAkrP.length) {break;}" fullword ascii
    $s11 = "return new ActiveXObject(ZudI);" fullword ascii
    $s12 = "function LhhSrof(ycsC,zboPn) {" fullword ascii
    $s13 = "return Jcj.split(PWFTo);" fullword ascii
    $s14 = "function obom(JlXxh,oFcpM) {" fullword ascii
    $s15 = "function JUWAt(HEDBzXvt,lKpO) {" fullword ascii
    $s16 = "function XyEib(hQLZwi) {" fullword ascii
    $s17 = "function XOei(tFuQW) {" fullword ascii
    $s18 = "return VHmxR;" fullword ascii
    $s19 = "function COQI(GAkrP) {" fullword ascii
    $s20 = "function jdNVzXyp(KiYU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}