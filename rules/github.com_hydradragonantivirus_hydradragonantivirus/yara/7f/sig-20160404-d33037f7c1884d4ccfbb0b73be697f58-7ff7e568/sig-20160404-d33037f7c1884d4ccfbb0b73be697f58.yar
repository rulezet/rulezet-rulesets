rule sig_20160404_d33037f7c1884d4ccfbb0b73be697f58 {
  meta:
    description = "datamaliciousorder - file 20160404_d33037f7c1884d4ccfbb0b73be697f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe0e951621e43ccc69219f8bfcd6f889f5ed6d858a1ae570cbcf1f47a50c7d86"

  strings:
    $s1  = "var HQ = true  , oJZb = OKj[7] + OKj[9] + OKj[11];" fullword ascii
    $s2  = "return EYhLgJG[0] + EYhLgJG[2] + EYhLgJG[4] + \".F\" + EYhLgJG[7] + EYhLgJG[9] + EYhLgJG[12] + EYhLgJG[14];" fullword ascii
    $s3  = "var EYhLgJG = PVBzO(AJFoSbmxyr+\" \"+\"System lM dOiRz Obj FpfAMN ect RCcdcxe DMvck\", \" \");" fullword ascii
    $s4  = "cewt.open(tmMkO,ndJOb,false);" fullword ascii
    $s5  = "var OKj = (\"2.XMLHTTP aTftTKP rgFZV XML ream St NeWnevSo AD dhqlKBZ O Uwle D\").split(\" \");" fullword ascii
    $s6  = "return mcdh;" fullword ascii
    $s7  = "function NeWnkV(MXdzIXR) {" fullword ascii
    $s8  = "function FALv(HXPNp) {" fullword ascii
    $s9  = "function yFYulaUbe(mabzBRYXTiM) {" fullword ascii
    $s10 = "return new ActiveXObject(LXTi);" fullword ascii
    $s11 = "function NwHh(YWaBC) {" fullword ascii
    $s12 = "if (YWaBC > 178727-660){return true;} else {return false;}" fullword ascii
    $s13 = "if(D>=Q.length) {break;}" fullword ascii
    $s14 = "return oyxVt.status;" fullword ascii
    $s15 = "return SsKga;" fullword ascii
    $s16 = "qkb = D; break; " fullword ascii
    $s17 = "return fvlnkAO;" fullword ascii
    $s18 = "function nEXi(bWeEo) {" fullword ascii
    $s19 = "function qCnu(cWvgn,ndJOb,tmMkO) {" fullword ascii
    $s20 = "function PVBzO(sbZ,OTsWU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}