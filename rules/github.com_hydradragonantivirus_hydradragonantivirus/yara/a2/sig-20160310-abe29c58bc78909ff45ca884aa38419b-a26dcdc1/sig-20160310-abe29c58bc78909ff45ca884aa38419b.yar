rule sig_20160310_abe29c58bc78909ff45ca884aa38419b {
  meta:
    description = "datamaliciousorder - file 20160310_abe29c58bc78909ff45ca884aa38419b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9931c806b75e210e30e8fbcb5f3184b50e1fba018b91b5e710b8b73a79f4c388"

  strings:
    $s1  = "var ea = true  , PKSx = ema[7] + ema[9] + ema[11];" fullword ascii
    $s2  = "return pfcvyng[0] + pfcvyng[2] + pfcvyng[4] + \".F\" + pfcvyng[7] + pfcvyng[9] + pfcvyng[12] + pfcvyng[14];" fullword ascii
    $s3  = "var ema = (\"2.XMLHTTP GyGVIyM BSTie XML ream St QQHcyXJj AD hdfgmmj O VAqV D\").split(\" \");" fullword ascii
    $s4  = "var pfcvyng = \"Sc pZGTwgH r axLmiXqrK ipting PVPEGpw PtZ ile xFOAHxvzhJzGWv System wG TcdpH Obj daetei ect TaOhQFp\".split(\" " ascii
    $s5  = "FbgRL.open(GYxxW,sTPMO,false);" fullword ascii
    $s6  = "function ZbRE(FbgRL,sTPMO,GYxxW) {" fullword ascii
    $s7  = "XLw = S; break; " fullword ascii
    $s8  = "return GODbd.status;" fullword ascii
    $s9  = "function ccmA(OtUxS,vHVan) {" fullword ascii
    $s10 = "function JmVLV(vlZqjr) {" fullword ascii
    $s11 = "function FHyyRLg(dAFA) {" fullword ascii
    $s12 = "if (e >= SrtPN.length) {break;}" fullword ascii
    $s13 = "function LbpPnSQrk(bPwdmRYGHJq) {" fullword ascii
    $s14 = "if (dFHTD > 164712-191){return true;} else {return false;}" fullword ascii
    $s15 = "return QXhJzb.position=614-614;" fullword ascii
    $s16 = "return xzdkWyY(iL,jmtbz[229-223]+jmtbz[906-899]+jmtbz[156-148]);" fullword ascii
    $s17 = "return WxIEg;" fullword ascii
    $s18 = "return RKblGtL" fullword ascii
    $s19 = "if (SZaBl == 439-239){return true;} else {return false;}" fullword ascii
    $s20 = "return ymZP.ExpandEnvironmentStrings(VduAW);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}