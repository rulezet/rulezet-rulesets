rule sig_20160322_ec49bc2ba110b45dc72c4cee20cd9420 {
  meta:
    description = "datamaliciousorder - file 20160322_ec49bc2ba110b45dc72c4cee20cd9420.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a239dbc8d763a4a9941806742180857abfb39051c7efd1b4e7c6b47de79815e0"

  strings:
    $s1  = "return WScript.CreateObject(nqeON);" fullword ascii
    $s2  = "return RVREyhH[0] + RVREyhH[2] + RVREyhH[4] + \".F\" + RVREyhH[7] + RVREyhH[9] + RVREyhH[12] + RVREyhH[14];" fullword ascii
    $s3  = "var Kv = true  , YObz = iwk[7] + iwk[9] + iwk[11];" fullword ascii
    $s4  = "var iwk = (\"2.XMLHTTP nxvXuuw cUbLr XML ream St PVpGWDmY AD yKWvAbb O QhKZ D\").split(\" \");" fullword ascii
    $s5  = "var RVREyhH = IMhKP(FVZAaSiBFg+\" \"+\"System IL ENjkl Obj mvpEpd ect CJhOheu KtZAw\", \" \");" fullword ascii
    $s6  = "BBtQs.open(AAWUi,lAFXl,false);" fullword ascii
    $s7  = "if(n>=M.length) {break;}" fullword ascii
    $s8  = "function sXrhH(AjFUkK) {" fullword ascii
    $s9  = "return lkOIffX(sT,WPhFg[210-204]+WPhFg[374-367]+WPhFg[988-980]);" fullword ascii
    $s10 = "function lkOIffX(acZc,vZaGJ) {" fullword ascii
    $s11 = "return LSPLO.status;" fullword ascii
    $s12 = "function HkhZzzw(SfkN) {" fullword ascii
    $s13 = "function Iwdn(BBtQs,lAFXl,AAWUi) {" fullword ascii
    $s14 = "if (pIdBO > 156688-984){return true;} else {return false;}" fullword ascii
    $s15 = "function pkuWVgZpH(BGklrOztHHU) {" fullword ascii
    $s16 = "return AjFUkK.position=480-480;" fullword ascii
    $s17 = "function FWyM(qPStM) {" fullword ascii
    $s18 = "if (l >= qPStM.length) {break;}" fullword ascii
    $s19 = "function lqtS(QhIWj) {" fullword ascii
    $s20 = "function oXEl(XBRRC,GHRVN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}