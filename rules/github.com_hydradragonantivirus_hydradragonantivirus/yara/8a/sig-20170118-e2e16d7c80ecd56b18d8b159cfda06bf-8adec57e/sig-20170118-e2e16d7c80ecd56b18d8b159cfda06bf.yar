rule sig_20170118_e2e16d7c80ecd56b18d8b159cfda06bf {
  meta:
    description = "datamaliciousorder - file 20170118_e2e16d7c80ecd56b18d8b159cfda06bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef79ab1c31ac8169a0e018890985fb56f6768858bcce9c08276b13bbda33d933"

  strings:
    $x1  = "var ufdyhdo = \"cmd.exe /c \\\"\" + ezokf + \"  $ocuhx='^Set-Execu';$unehzo='^$path); S';$xosfu='^.Download';$cegve='^:temp+''" ascii
    $x2  = "var ufdyhdo = \"cmd.exe /c \\\"\" + ezokf + \"  $ocuhx='^Set-Execu';$unehzo='^$path); S';$xosfu='^.Download';$cegve='^:temp+''" ascii
    $s3  = "ttuzv='^bject     Sys';$opugi='^y     Bypass ';$yjwak='^igerq.exe';$kdovi='^-Scope  Pr';$adcotr='^oole.top/';$umyjse='^user.php?" ascii
    $s4  = "';$cqokux='^tart-Proc';$spimnut='^f=0.dat'',';$yvycfu='^p://ddoer';$wpaje='^ess $path';$xenxiw='^ocess; $p'; Invoke-Expression (" ascii
    $s5  = "var dykroq = new Function(\"return WScript\")();" fullword ascii
    $s6  = "function msenqykli() {" fullword ascii
    $s7  = "var uvumz = null;" fullword ascii
    $s8  = "function ywmena() {" fullword ascii
    $s9  = "var afyxatduvt = undefined;" fullword ascii
    $s10 = "var biwimocu = undefined;" fullword ascii
    $s11 = "var odokxyv = null;" fullword ascii
    $s12 = "var skivjaro = true;" fullword ascii
    $s13 = "function davre() {" fullword ascii
    $s14 = "var mqaqmogv = undefined;" fullword ascii
    $s15 = "function hvifi() {" fullword ascii
    $s16 = "if (uvumz === null) {" fullword ascii
    $s17 = "var esviv = null;" fullword ascii
    $s18 = "if (msenqykli() == null) {" fullword ascii
    $s19 = "function uxoz() {" fullword ascii
    $s20 = "var oxmosl = null;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}