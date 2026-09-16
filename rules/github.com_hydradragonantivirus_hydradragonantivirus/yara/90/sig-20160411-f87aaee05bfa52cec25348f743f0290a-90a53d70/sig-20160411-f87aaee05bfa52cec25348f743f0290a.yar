rule sig_20160411_f87aaee05bfa52cec25348f743f0290a {
  meta:
    description = "datamaliciousorder - file 20160411_f87aaee05bfa52cec25348f743f0290a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c1b355ccc19e929fae1a5ba97e52e82d13b7a44560a83caf04b5b1b925d367d"

  strings:
    $s1  = "return dShqmXk[0] + dShqmXk[2] + dShqmXk[4] + \".F\" + dShqmXk[7] + dShqmXk[9] + dShqmXk[12] + dShqmXk[14];" fullword ascii
    $s2  = "var os = true  , VpTA = Jsz[7] + Jsz[9] + Jsz[11];" fullword ascii
    $s3  = "var Jsz = (\"2.XMLHTTP DPnfCIs CvRcZ XML ream St WUIXjiaW AD wFjywVf O WLLr D\").split(\" \");" fullword ascii
    $s4  = "sSxK.open(lFLLD,Giyff,false);" fullword ascii
    $s5  = "if(d>=J.length) {break;}" fullword ascii
    $s6  = "function srWb(hPVHV,uBsIr) {" fullword ascii
    $s7  = "return KXHED;" fullword ascii
    $s8  = "return ShKo[BqJwLNn[0]+BqJwLNn[1]];" fullword ascii
    $s9  = "return kLdbLEx[0];" fullword ascii
    $s10 = "return dfKWWoG;" fullword ascii
    $s11 = "function XjgwvsE(ShKo) {" fullword ascii
    $s12 = "function ZtThE(uuexGY) {" fullword ascii
    $s13 = "return kIBsMZ[IrKq[660-660]]=991-991;" fullword ascii
    $s14 = "return new ActiveXObject(ZqSa);" fullword ascii
    $s15 = "if (q >= vDSmz.length) {break;}" fullword ascii
    $s16 = "function genXCsaz(WRp) {" fullword ascii
    $s17 = "function yRYG(KpzWk) {" fullword ascii
    $s18 = "function ovZOfJbVp(edeNf) {" fullword ascii
    $s19 = "if (whcpb > 178668-910){return true;} else {return false;}" fullword ascii
    $s20 = "function uDDxnG(lTLTBcc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}