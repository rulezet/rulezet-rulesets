rule sig_20170119_54c17af0b29af374d4eae3885ccfc073 {
  meta:
    description = "datamaliciousorder - file 20170119_54c17af0b29af374d4eae3885ccfc073.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f03fe087dc3da2707f0006c85d79adeb39ea9109ad127d18095b6dd1f77d38f1"

  strings:
    $x1  = "var yxhebet = \"cmd.exe /c \\\"\" + eqdidahk + \"  $ykdux='^can.exe'');(New-O';$ygiz='^loadFile(''http:/';$akvaba='^-Process $pa" ascii
    $x2  = "var yxhebet = \"cmd.exe /c \\\"\" + eqdidahk + \"  $ykdux='^can.exe'');(New-O';$ygiz='^loadFile(''http:/';$akvaba='^-Process $pa" ascii
    $s3  = "eztywu='^icy   Bypass  -Scop';$gydpe='^Set-ExecutionPol';$yjom='^/user.php?f=0.da';$npytkex='^bject   System.Net';$fkoky='^.Webc" ascii
    $s4  = "lient).Down';$ypgys='^=($env:temp+''\\ig';$lqyqba='^t'',$path); Start';$uzewtu='^/fortycooola.top';$amuny='^e     Process; $path" ascii
    $s5  = "var maqvi = new Function(\"return WScript\")();" fullword ascii
    $s6  = "if (efkeputo == undefined) {" fullword ascii
    $s7  = "function hozo() {" fullword ascii
    $s8  = "var orobi = undefined;" fullword ascii
    $s9  = "function utyqtalarb() {" fullword ascii
    $s10 = "switch (iztidhisy) {" fullword ascii
    $s11 = "var ckewamtevh = undefined;" fullword ascii
    $s12 = "var byrgi = true;" fullword ascii
    $s13 = "function fofo() {" fullword ascii
    $s14 = "return okuqqe;" fullword ascii
    $s15 = "var jwirit = null;" fullword ascii
    $s16 = "function uzywibly() {" fullword ascii
    $s17 = "function johy() {" fullword ascii
    $s18 = "var jaqubeml = false;" fullword ascii
    $s19 = "return otulygru;" fullword ascii
    $s20 = "var ytcedumo = undefined;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}