rule sig_20160404_1894a9176eef40450e36b2d299bebbb0 {
  meta:
    description = "datamaliciousorder - file 20160404_1894a9176eef40450e36b2d299bebbb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bb32bff188e1761cb91f3ececd6bd3645a08df25324ea9dbb71e3c8b09166a1"

  strings:
    $s1  = "var CC = true  , KMJD = CnS[7] + CnS[9] + CnS[11];" fullword ascii
    $s2  = "return obdMPwr[0] + obdMPwr[2] + obdMPwr[4] + \".F\" + obdMPwr[7] + obdMPwr[9] + obdMPwr[12] + obdMPwr[14];" fullword ascii
    $s3  = "var CnS = (\"2.XMLHTTP bllBjsy FZSAy XML ream St tjjGdLMD AD vsqQvPj O XVJB D\").split(\" \");" fullword ascii
    $s4  = "var obdMPwr = tcykf(mfWktFLtMm+\" \"+\"System ws ahPky Obj MBuRYW ect bQOaiVo dklRO\", \" \");" fullword ascii
    $s5  = "WVqD.open(KRzqu,rZjeA,false);" fullword ascii
    $s6  = "function XXJWAx(ZCki,fAWTEV) {" fullword ascii
    $s7  = "function ydsf(VbCzu) {" fullword ascii
    $s8  = "function BwMi(ZfIKM) {" fullword ascii
    $s9  = "return MbDDQDQ;" fullword ascii
    $s10 = "return ooT.split(ugRlA);" fullword ascii
    $s11 = "function EQjVF(htEmUv) {" fullword ascii
    $s12 = "return RYdHJ;" fullword ascii
    $s13 = "function jkTi(oMhCd,pWsEp) {" fullword ascii
    $s14 = "function WqnM(okNeN) {" fullword ascii
    $s15 = "function hKIh(lTxLD) {" fullword ascii
    $s16 = "function mDcy(lzcWR) {" fullword ascii
    $s17 = "function vjPGy(rLvQzy) {" fullword ascii
    $s18 = "function xbztdkOr(xCu) {" fullword ascii
    $s19 = "var SxfEger = \"eVblHb*jxg*pt.S\"+\"hell*xDJVlMS*Scri*\";" fullword ascii
    $s20 = "function lBGUk(bukFHJDg,MXaz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}