rule sig_20160303_5c61d8844f9906dc0ba0f0209ed9b07b {
  meta:
    description = "datamaliciousorder - file 20160303_5c61d8844f9906dc0ba0f0209ed9b07b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67bac97822dfbe531d78842c0797de96be43f37feaada543b0d286845640e99a"

  strings:
    $s1  = "var yLFkW = \"hYEsOi Wbt pt.Shell ZhAqHoj Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var LTY = (geO + \"TTP\" + \" aWxkDCl zijMy XML ream St aQPwlOIV AD sslPOLD OD\").split(\" \");" fullword ascii
    $s3  = "return SwKKJYl[0] + SwKKJYl[2] + SwKKJYl[4] + \".F\" + SwKKJYl[7] + SwKKJYl[9] + SwKKJYl[12] + SwKKJYl[14];" fullword ascii
    $s4  = "var vg = true  , ledN = LTY[7] + \"\" + LTY[9];" fullword ascii
    $s5  = "var SwKKJYl = \"Sc fbIzqQr r mbZhaCPuq ipting AYlZlYM ZDr ile pzyrCjGWHEsCho System fo ygQpO Obj nBdIDj ect TniwJiT\".split(\" " ascii
    $s6  = "OMaDB.open(neSZX,tEsml,false);" fullword ascii
    $s7  = "qnE = i; break; " fullword ascii
    $s8  = "function HKYMqzYm() {" fullword ascii
    $s9  = "function sULn(LjLtW) {" fullword ascii
    $s10 = "return eXKIe;" fullword ascii
    $s11 = "return uCbTC.status;" fullword ascii
    $s12 = "function TAGfeNCbJ(ivMLSHbpWpn) {" fullword ascii
    $s13 = "function oUho(uCbTC) {" fullword ascii
    $s14 = "function dOOQS(RyTeSR) {" fullword ascii
    $s15 = "function VXCf(urvSX) {" fullword ascii
    $s16 = "function apry(QNPfu) {" fullword ascii
    $s17 = "function yuvy(OMaDB,tEsml,neSZX) {" fullword ascii
    $s18 = "function MKGZ(huNhC) {" fullword ascii
    $s19 = "function nCFO(vhsdZ,fmetc) {" fullword ascii
    $s20 = "function ZHdGsbL(rfbe) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}