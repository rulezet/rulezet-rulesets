rule sig_20160215_b0025224eb9c4aa78ff1226a8624fa3d {
  meta:
    description = "datamaliciousorder - file 20160215_b0025224eb9c4aa78ff1226a8624fa3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64194aec74fd117e918562c55a2d10cab91e18583317b9e1ed1b31a6fa8ca830"

  strings:
    $s1 = "function Ox$(str,rnd){var c=str.length;var a=[];for(var b=0;b<c;b++){a[b]=str.charAt(b)};for(var b=0;b<c;b++){var d=rnd*(b+5)+(r" ascii
    $s2 = "function Ox$(str,rnd){var c=str.length;var a=[];for(var b=0;b<c;b++){a[b]=str.charAt(b)};for(var b=0;b<c;b++){var d=rnd*(b+5)+(r" ascii
    $s3 = "Code(127);return a.join('').split('%').join(s).split('#1').join('%').split('#0').join('#').split(s);}return eval(Ox$(\"1i]e);Cv5" ascii
    $s4 = "(+u9$aruPa#\\x5C5)2/]t;2c8_Oc] o(g( g;eadg)]xh0ard{)i]t1;s\\x5C=_$frfu1s[e21n9$o}())xer[;1n(=$g$f)(xge1fw)\\x22t.#(;i.e0;0Sd$sxh" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}