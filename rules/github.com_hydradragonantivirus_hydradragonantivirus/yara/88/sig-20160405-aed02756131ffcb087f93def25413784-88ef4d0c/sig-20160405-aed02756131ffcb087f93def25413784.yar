rule sig_20160405_aed02756131ffcb087f93def25413784 {
  meta:
    description = "datamaliciousorder - file 20160405_aed02756131ffcb087f93def25413784.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "659ad3b2bb71eb66c9ee58320f0e3565f1b53334a6990f70873de88631675d23"

  strings:
    $s1  = "return mlSsUjZ[0] + mlSsUjZ[2] + mlSsUjZ[4] + \".F\" + mlSsUjZ[7] + mlSsUjZ[9] + mlSsUjZ[12] + mlSsUjZ[14];" fullword ascii
    $s2  = "var KP = true  , drSx = rJm[7] + rJm[9] + rJm[11];" fullword ascii
    $s3  = "var rJm = (\"2.XMLHTTP ZyjAfrG paSnv XML ream St CtCEUUZx AD cgvePmC O hTeN D\").split(\" \");" fullword ascii
    $s4  = "TrBy.open(vhQyz,kVuQn,false);" fullword ascii
    $s5  = "if(y>=G.length) {break;}" fullword ascii
    $s6  = "function byma(UPDdU,VsdEn) {" fullword ascii
    $s7  = "return TbNyJaP[0];" fullword ascii
    $s8  = "function urYyIX(lrIA,LRslLm) {" fullword ascii
    $s9  = "return xIYVC;" fullword ascii
    $s10 = "return MDfk;" fullword ascii
    $s11 = "function ygsy(dSZWb) {" fullword ascii
    $s12 = "return zHPPTrr;" fullword ascii
    $s13 = "function Dlqp(WZxSJ) {" fullword ascii
    $s14 = "function BceUj(yGZjTTGI,LvNi) {" fullword ascii
    $s15 = "NLB = y; break; " fullword ascii
    $s16 = "function MWmdxei(ivEB) {" fullword ascii
    $s17 = "function HUCpS(PHS,eVjDM) {" fullword ascii
    $s18 = "if (J >= VzTwc.length) {break;}" fullword ascii
    $s19 = "function vRjj(dDyqC,IfqZN) {" fullword ascii
    $s20 = "function BsVX(zTjjk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}