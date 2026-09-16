rule sig_20160312_3e4ac744223a8a2aa19668f1d4e48b6e {
  meta:
    description = "datamaliciousorder - file 20160312_3e4ac744223a8a2aa19668f1d4e48b6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a57e21e5cd1b9ba0af53a14cd2b1f707ddaf9b7e40d37f66b061b6415e02d469"

  strings:
    $s1  = "return ajNUZsu[0] + ajNUZsu[2] + ajNUZsu[4] + \".F\" + ajNUZsu[7] + ajNUZsu[9] + ajNUZsu[12] + ajNUZsu[14];" fullword ascii
    $s2  = "var XH = true  , DHBi = FfT[7] + FfT[9] + FfT[11];" fullword ascii
    $s3  = "eZLLg.open(Fhlnb,zCHjI,false);" fullword ascii
    $s4  = "var FfT = (\"2.XMLHTTP pgaxaFx jqkxf XML ream St uchyHVvz AD CGQYWDl O WiLD D\").split(\" \");" fullword ascii
    $s5  = "if(N>=V.length) {break;}" fullword ascii
    $s6  = "return vQKZkqo(yD,mIJHI[427-421]+mIJHI[726-719]+mIJHI[222-214]);" fullword ascii
    $s7  = "function gTRUv(IEYwJZ) {" fullword ascii
    $s8  = "if (j >= tEBdH.length) {break;}" fullword ascii
    $s9  = "return vSug.ExpandEnvironmentStrings(QfDkz);" fullword ascii
    $s10 = "function ARPq(suewp,hwMGc) {" fullword ascii
    $s11 = "function FvOK(yvIEE) {" fullword ascii
    $s12 = "function meIrjDKy() {" fullword ascii
    $s13 = "function fTRo(eoCKp,QpDRN) {" fullword ascii
    $s14 = "function NImT(WFscM) {" fullword ascii
    $s15 = "function XeWW(nPluD) {" fullword ascii
    $s16 = "function vQKZkqo(vSug,QfDkz) {" fullword ascii
    $s17 = "function doRLzpVd(NBlIP,FqYuoQ) {" fullword ascii
    $s18 = "return XAc.size;" fullword ascii
    $s19 = "function ixcjGrVdm() {" fullword ascii
    $s20 = "return oBdopcz" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}