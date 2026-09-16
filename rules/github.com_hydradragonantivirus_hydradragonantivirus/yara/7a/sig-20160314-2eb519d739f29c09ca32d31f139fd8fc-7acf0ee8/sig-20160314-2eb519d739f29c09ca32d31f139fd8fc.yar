rule sig_20160314_2eb519d739f29c09ca32d31f139fd8fc {
  meta:
    description = "datamaliciousorder - file 20160314_2eb519d739f29c09ca32d31f139fd8fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5eee4c3952a648c6e2e9068234a02b575757b50f54876c515b2ff1e74567640"

  strings:
    $s1  = "var Rh = true  , YZMG = jdE[7] + jdE[9] + jdE[11];" fullword ascii
    $s2  = "return ZrUKJHw[0] + ZrUKJHw[2] + ZrUKJHw[4] + \".F\" + ZrUKJHw[7] + ZrUKJHw[9] + ZrUKJHw[12] + ZrUKJHw[14];" fullword ascii
    $s3  = "var ZrUKJHw = fyMZu(\"Sc sftSEtZ r LKTLHphyR ipting giZtHPt EGn ile ckcsXiGedUqpnc System Rf FHVEa Obj uXAqjb ect RYKVvgT aJjwN" ascii
    $s4  = "mjxEY.open(aIBeB,sDwdS,false);" fullword ascii
    $s5  = "var ZrUKJHw = fyMZu(\"Sc sftSEtZ r LKTLHphyR ipting giZtHPt EGn ile ckcsXiGedUqpnc System Rf FHVEa Obj uXAqjb ect RYKVvgT aJjwN" ascii
    $s6  = "var jdE = (\"2.XMLHTTP ZUyIIkC ATSMJ XML ream St ZxtHkrrr AD mrCjTxI O UjhF D\").split(\" \");" fullword ascii
    $s7  = "Cnj = A; break; " fullword ascii
    $s8  = "function fyMZu(kOu,RjfYf) {" fullword ascii
    $s9  = "return kOu.split(RjfYf);" fullword ascii
    $s10 = "return Fuvb.responseBody;" fullword ascii
    $s11 = "function GxOP(SlAdS) {" fullword ascii
    $s12 = "function YzKy(nXWzM) {" fullword ascii
    $s13 = "function wwyN(PtRBI) {" fullword ascii
    $s14 = "function Fkyt(mjxEY,sDwdS,aIBeB) {" fullword ascii
    $s15 = "function lgep(EDuqf) {" fullword ascii
    $s16 = "return new ActiveXObject(cbSXYm);" fullword ascii
    $s17 = "function lgpw(BRpWa) {" fullword ascii
    $s18 = "if(A>=T.length) {break;}" fullword ascii
    $s19 = "function EjlJZ(cbSXYm) {" fullword ascii
    $s20 = "if (vWBTR == 858-658){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}