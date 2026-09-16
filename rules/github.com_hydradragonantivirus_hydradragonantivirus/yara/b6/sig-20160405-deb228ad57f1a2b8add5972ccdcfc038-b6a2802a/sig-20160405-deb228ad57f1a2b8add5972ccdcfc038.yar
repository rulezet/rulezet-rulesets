rule sig_20160405_deb228ad57f1a2b8add5972ccdcfc038 {
  meta:
    description = "datamaliciousorder - file 20160405_deb228ad57f1a2b8add5972ccdcfc038.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96dc63945cc9fa1c81dfff23d9504871bf8a36c5a0885fcc648a8fc706bcab47"

  strings:
    $s1  = "return aZcZiVj[0] + aZcZiVj[2] + aZcZiVj[4] + \".F\" + aZcZiVj[7] + aZcZiVj[9] + aZcZiVj[12] + aZcZiVj[14];" fullword ascii
    $s2  = "var MSs = zZEC(AsAK + \"B.\" + kzB[5]+(288077, kzB[4]));" fullword ascii
    $s3  = "var bN = true  , AsAK = kzB[7] + kzB[9] + kzB[11];" fullword ascii
    $s4  = "FMVq.open(VMLas,fOQKN,false);" fullword ascii
    $s5  = "var kzB = (\"2.XMLHTTP XBsmLtZ AphRX XML ream St WIRPnYEM AD pUFAsNA O pyZg D\").split(\" \");" fullword ascii
    $s6  = "function wXWrIMJH(iNI) {" fullword ascii
    $s7  = "function fkwm(Jvmqg) {" fullword ascii
    $s8  = "function efth(iEfRk) {" fullword ascii
    $s9  = "function LjdsLrK(ulKU,paYRl) {" fullword ascii
    $s10 = "function GPMsav(gNyf,vYgEQQ) {" fullword ascii
    $s11 = "return uMZhjDG;" fullword ascii
    $s12 = "return ytDb[fzUeGp[0]];" fullword ascii
    $s13 = "return kdM.split(gJPhe);" fullword ascii
    $s14 = "function APcY(NncDO) {" fullword ascii
    $s15 = "function zZEC(cpgZO) {" fullword ascii
    $s16 = "function VuveppYwL(kQLTkUUfdTz) {" fullword ascii
    $s17 = "if (NncDO == 799-599){return true;} else {return false;}" fullword ascii
    $s18 = "return vlLta;" fullword ascii
    $s19 = "function dWjn(YqvOi) {" fullword ascii
    $s20 = "function AOeWs(oCoYfGWe,PKJz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}