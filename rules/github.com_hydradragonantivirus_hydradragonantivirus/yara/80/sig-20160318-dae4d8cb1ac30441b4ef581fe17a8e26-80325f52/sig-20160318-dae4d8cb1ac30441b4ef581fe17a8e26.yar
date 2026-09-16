rule sig_20160318_dae4d8cb1ac30441b4ef581fe17a8e26 {
  meta:
    description = "datamaliciousorder - file 20160318_dae4d8cb1ac30441b4ef581fe17a8e26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4c0461376b90f10754aba28a9f5ae55439a6bce47880100680de075e32c16ee"

  strings:
    $x1 = "var a=[\"http://jisoeieix.net/eiissjn/ajsoosdj/83930/si.php\",\"http://www.edilmarmoceramic.it/lineaceramic/ssd.exe\",\"http://5" ascii
    $x2 = ".56.4.54/isjd/js/db/www/forum.php\",\"http://78.83.75.75/eaavmutdstem/firefox/dop/sdfeyere.html\",\"length\",\"WScript.Shell\"," ascii
    $s3 = "var c=f[a[7]](a[6])+String[a[8]](92)+Math[a[10]](Math[a[9]]()*100000000)+a[11];//19" fullword ascii
    $s4 = "function b()" fullword ascii
    $s5 = "g[a[17]](a[25],e[d],false);//41" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}