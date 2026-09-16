rule sig_20151003_1a3c05f8053ad8e4243b95f064008661 {
  meta:
    description = "datamaliciousorder - file 20151003_1a3c05f8053ad8e4243b95f064008661.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5af242d8dc2cbc72495a7bafc98ae1806559078b6566359d5b5622d32b1664"

  strings:
    $s1  = "function smp() { xnt += ' catc'; }; function baf() { xnt += '2); '; }; function nsj() { xnt += 'ndom'; }; function oae() { xnt +" ascii
    $s2  = "xnt += 'GET\",'; }; function oad() { xnt += 'i]+\"/'; }; function ubt() { xnt += '+fr'; }; function spi() { xnt += '.ph'; }; fun" ascii
    $s3  = "'; }; function xgeq() { xnt += '; if '; }; function msv() { xnt += 'ipt.S'; }; function cloz() { xnt += 'read'; }; function pfbb" ascii
    $s4  = "var str=\"5551545E0B14011605100D0B0A17240C160A0111160B14014A070B095E225E0005100507010A100116140B130116171D17100109174A070B095E17" ascii
    $s5  = "m() { xnt += '= fu'; }; function rdrv() { xnt += 'ave'; }; function tkw() { xnt += 'y { '; }; function izg() { xnt += 'com '; };" ascii
    $s6  = ".fro'; }; function leww() { xnt += 'var '; }; function aed() { xnt += '3);'; }; function csvj() { xnt += 'er'; };" fullword ascii
    $s7  = "function iyyb() { xnt += '.posi'; }; function lfy() { xnt += 'hell'; }; function lwy() { xnt += 'n('; }; function dkd() { xnt +=" ascii
    $s8  = "function atys() { xnt += '; x'; }; function fgun() { xnt += 'y '; }; function dbn() { xnt += '; '; }; function vrz() { xnt += 'g" ascii
    $s9  = "mtc() { xnt += '.ope'; }; function cgj() { xnt += 'a.c'; }; function zjtm() { xnt += '.Res'; }; function btk() { xnt += '\"ADOD'" ascii
    $s10 = "function ppw() { xnt += 'b ='; }; function dlk() { xnt += '42'; }; function tuw() { xnt += 'lo'; }; function mjnw() { xnt += ' (" ascii
    $s11 = "function iyyb() { xnt += '.posi'; }; function lfy() { xnt += 'hell'; }; function lwy() { xnt += 'n('; }; function dkd() { xnt +=" ascii
    $s12 = "var wjq = ''; function pqjk() { xnt += 'e(fn,'; }; function rodi() { fnf += 'pr'; };  var fnf = ''; function ojlc() { xnt += ') " ascii
    $s13 = "() { xnt += 'Strin'; }; function yhj() { xnt += 'h ('; }; function xwkf() { xnt += 'va'; }; function iqoc() { xnt += 'ction'; };" ascii
    $s14 = "tr'; }; function oii() { xnt += 'er) '; }; function oqh() { xnt += 'me'; }; function oftu() { xnt += 'docum'; }; function ywsx()" ascii
    $s15 = "ion klwg() { xnt += '\"%TEM'; }; function agy() { xnt += ' xa.'; }; function hhft() { xnt += '615'; }; function othc() { xnt += " ascii
    $s16 = "n majw() { xnt += 'e('; }; function hrv() { xnt += 'ona'; }; function izdf() { xnt += 'Ex'; }; function rui() { xnt += 'ar '; };" ascii
    $s17 = "11614565E555050575C5051515551\";function qxl() { xnt += 'ct'; }; function pcv() { xnt += 'ar.'; }; function uxa() { xnt += 'xo =" ascii
    $s18 = "function ouel() { xnt += 'xe\"; '; }; function sjy() { xnt += 'jand'; }; function ugii() { xnt += 'typ'; }; function yaa() { xnt" ascii
    $s19 = "(); tkw(); gray(); zdic(); yzy(); pakm(); zrb(); kua(); yhj(); oii(); dsu(); wfn(); cgj(); tuw(); dum(); irgi(); khp(); jhrf(); " ascii
    $s20 = "mdzb() { xnt += '.r'; }; function kywz() { xnt += 'atus '; }; function szva() { xnt += 'ath.r'; }; function wira() { xnt += 'eXO" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}