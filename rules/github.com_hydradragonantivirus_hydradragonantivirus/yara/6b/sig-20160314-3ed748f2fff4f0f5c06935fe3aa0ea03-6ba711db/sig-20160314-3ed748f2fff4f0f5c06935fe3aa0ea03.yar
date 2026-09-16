rule sig_20160314_3ed748f2fff4f0f5c06935fe3aa0ea03 {
  meta:
    description = "datamaliciousorder - file 20160314_3ed748f2fff4f0f5c06935fe3aa0ea03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc3ca509a51c91166a726501b03fe7a5004ed76911de4d354a04d20573750ad0"

  strings:
    $s1  = "function okfIC(KfB,TdlLr) {" fullword ascii
    $s2  = "return KfB.split(TdlLr);" fullword ascii
    $s3  = "return TQJbKIR[0] + TQJbKIR[2] + TQJbKIR[4] + \".F\" + TQJbKIR[7] + TQJbKIR[9] + TQJbKIR[12] + TQJbKIR[14];" fullword ascii
    $s4  = "var jL = true  , WBFr = pem[7] + pem[9] + pem[11];" fullword ascii
    $s5  = "mBKbl.open(djNOn,KXddE,false);" fullword ascii
    $s6  = "var TQJbKIR = okfIC(\"Sc nDGTYhd r exmprRqdn ipting VYTPVby cwJ ile GJLXTiKrJnflwk System II fQdoI Obj sGXsSf ect JOjYWJv meSBv" ascii
    $s7  = "var TQJbKIR = okfIC(\"Sc nDGTYhd r exmprRqdn ipting VYTPVby cwJ ile GJLXTiKrJnflwk System II fQdoI Obj sGXsSf ect JOjYWJv meSBv" ascii
    $s8  = "var pem = (\"2.XMLHTTP IILNlab uJkGC XML ream St mljKliTF AD csvpKZe O dyrC D\").split(\" \");" fullword ascii
    $s9  = "function YMpF(FFUYX) {" fullword ascii
    $s10 = "function nEHhQblcf(FOMvbXsPgRq) {" fullword ascii
    $s11 = "function FCfr(svOLl) {" fullword ascii
    $s12 = "XkH = M; break; " fullword ascii
    $s13 = "function RQvWj(GofsHD) {" fullword ascii
    $s14 = "return IUYRigG" fullword ascii
    $s15 = "if (B >= fqiai.length) {break;}" fullword ascii
    $s16 = "function hnhCuBS(iDtl) {" fullword ascii
    $s17 = "function hMEn(uIZGF,xCUTH) {" fullword ascii
    $s18 = "function vIVWDsoX(nDH) {" fullword ascii
    $s19 = "function TXBQ(ckYeK,PPafo) {" fullword ascii
    $s20 = "return new ActiveXObject(GofsHD);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}