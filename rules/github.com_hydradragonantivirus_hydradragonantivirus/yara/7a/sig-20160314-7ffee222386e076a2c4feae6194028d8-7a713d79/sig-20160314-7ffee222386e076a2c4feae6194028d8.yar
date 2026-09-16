rule sig_20160314_7ffee222386e076a2c4feae6194028d8 {
  meta:
    description = "datamaliciousorder - file 20160314_7ffee222386e076a2c4feae6194028d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73b7206798a22eb57e70485a179a8ce63f68937e2fc73c74080255d42adc50e8"

  strings:
    $s1  = "var TY = true  , rIWF = RYi[7] + RYi[9] + RYi[11];" fullword ascii
    $s2  = "return OAUaAeP[0] + OAUaAeP[2] + OAUaAeP[4] + \".F\" + OAUaAeP[7] + OAUaAeP[9] + OAUaAeP[12] + OAUaAeP[14];" fullword ascii
    $s3  = "var OAUaAeP = \"Sc MamIRvH r DZsawTuFn ipting vqTFJZp LFe ile UwCWrBSkEHVMLg System ry qMQsL Obj rJBJHq ect CPCDXYn rTIuz\".spli" ascii
    $s4  = "aqklm.open(ymAmd,fJdxG,false);" fullword ascii
    $s5  = "var RYi = (\"2.XMLHTTP qbznqoS HkQFu XML ream St jYGwNLdR AD dujCxBX O oreF D\").split(\" \");" fullword ascii
    $s6  = "var OAUaAeP = \"Sc MamIRvH r DZsawTuFn ipting vqTFJZp LFe ile UwCWrBSkEHVMLg System ry qMQsL Obj rJBJHq ect CPCDXYn rTIuz\".spli" ascii
    $s7  = "function hxFKTez(YpWa,JVeWT) {" fullword ascii
    $s8  = "if (h >= ugwdd.length) {break;}" fullword ascii
    $s9  = "function FhFSSkRjs() {" fullword ascii
    $s10 = "function igSp(mLuzV,GTNjc) {" fullword ascii
    $s11 = "function VMwp(ZCxhL) {" fullword ascii
    $s12 = "return YRly.responseBody;" fullword ascii
    $s13 = "return tTIcb;" fullword ascii
    $s14 = "function dANe(ZRzPa) {" fullword ascii
    $s15 = "function WylC(wQTtK) {" fullword ascii
    $s16 = "LKq = m; break; " fullword ascii
    $s17 = "return hxFKTez(mW,HpmKJ[479-473]+HpmKJ[595-588]+HpmKJ[836-828]);" fullword ascii
    $s18 = "if(m>=b.length) {break;}" fullword ascii
    $s19 = "function sOgImNyS() {" fullword ascii
    $s20 = "function oJcn(aqklm,fJdxG,ymAmd) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}