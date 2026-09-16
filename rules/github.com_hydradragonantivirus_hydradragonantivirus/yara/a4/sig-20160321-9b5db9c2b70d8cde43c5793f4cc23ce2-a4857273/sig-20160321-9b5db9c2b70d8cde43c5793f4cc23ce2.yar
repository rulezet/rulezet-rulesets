rule sig_20160321_9b5db9c2b70d8cde43c5793f4cc23ce2 {
  meta:
    description = "datamaliciousorder - file 20160321_9b5db9c2b70d8cde43c5793f4cc23ce2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3a3dd77ec19db628485c430710b98abfecdcb92741f3a37e8801d62715a7460"

  strings:
    $s1  = "return WScript.CreateObject(BWJTw);" fullword ascii
    $s2  = "return BXkvEyZ[0] + BXkvEyZ[2] + BXkvEyZ[4] + \".F\" + BXkvEyZ[7] + BXkvEyZ[9] + BXkvEyZ[12] + BXkvEyZ[14];" fullword ascii
    $s3  = "var kF = true  , DqnX = Wjv[7] + Wjv[9] + Wjv[11];" fullword ascii
    $s4  = "NeuhM.open(IqXAf,bDroo,false);" fullword ascii
    $s5  = "var BXkvEyZ = PxwlF(eIjCwtTAhd+\" \"+\"System Li KmzGt Obj QCrhDa ect lBoYbgE LXoJw\", \" \");" fullword ascii
    $s6  = "var Wjv = (\"2.XMLHTTP eJlynAA RcRoE XML ream St qWKZMWrS AD IVgyDhH O qLIF D\").split(\" \");" fullword ascii
    $s7  = "function RlYg(BWJTw) {" fullword ascii
    $s8  = "if (KtsvC == 426-226){return true;} else {return false;}" fullword ascii
    $s9  = "function iqyvhHvXs(NixwoImsXFo) {" fullword ascii
    $s10 = "return LRyo.ExpandEnvironmentStrings(VEuzT);" fullword ascii
    $s11 = "if(b>=o.length) {break;}" fullword ascii
    $s12 = "function gpZn(foiVa,yhDwP) {" fullword ascii
    $s13 = "if (whRFj > 169729-121){return true;} else {return false;}" fullword ascii
    $s14 = "return MmRQz.status;" fullword ascii
    $s15 = "return nWjWAeH(OV,KWWdU[974-968]+KWWdU[125-118]+KWWdU[392-384]);" fullword ascii
    $s16 = "function sBCYuxGu(sRvP) {" fullword ascii
    $s17 = "function OKEZkSfU(Myk) {" fullword ascii
    $s18 = "return UdR.split(ixDtR);" fullword ascii
    $s19 = "if (k >= clnqP.length) {break;}" fullword ascii
    $s20 = "rmx = b; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}