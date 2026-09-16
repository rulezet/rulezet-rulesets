rule sig_20160314_206efee8cd055b07d605d089fde90e5b {
  meta:
    description = "datamaliciousorder - file 20160314_206efee8cd055b07d605d089fde90e5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a25d398dc2534f4edd3eb4c935888570a9d2c27bee9c34b20ff42e7c3e7f052e"

  strings:
    $s1  = "var oH = true  , cMeN = yAh[7] + yAh[9] + yAh[11];" fullword ascii
    $s2  = "return rHSoODc[0] + rHSoODc[2] + rHSoODc[4] + \".F\" + rHSoODc[7] + rHSoODc[9] + rHSoODc[12] + rHSoODc[14];" fullword ascii
    $s3  = "var rHSoODc = \"Sc ZglhTcD r lbzOIOmml ipting xAVrEqM fsu ile GoFrOSnjenPEbO System ol jZXVl Obj fyknXh ect BwjjYTX gJymJ\".spli" ascii
    $s4  = "var rHSoODc = \"Sc ZglhTcD r lbzOIOmml ipting xAVrEqM fsu ile GoFrOSnjenPEbO System ol jZXVl Obj fyknXh ect BwjjYTX gJymJ\".spli" ascii
    $s5  = "var yAh = (\"2.XMLHTTP wVxJHUh AQXuZ XML ream St nzBguxTK AD Tnozawl O vFOu D\").split(\" \");" fullword ascii
    $s6  = "ZwRUc.open(MlhoA,OXgGc,false);" fullword ascii
    $s7  = "}catch(tZloGt){" fullword ascii
    $s8  = "function eNVt(jxoCr) {" fullword ascii
    $s9  = "return DHT.size;" fullword ascii
    $s10 = "return PDyu.responseBody;" fullword ascii
    $s11 = "if(k>=d.length) {break;}" fullword ascii
    $s12 = "function yEQq(dSSUs) {" fullword ascii
    $s13 = "function FCIC(wgDFW,zpHfp) {" fullword ascii
    $s14 = "return pHNkqI.position=752-752;" fullword ascii
    $s15 = "function OTlF(QHBfg) {" fullword ascii
    $s16 = "function nJssCfoJ(DHT) {" fullword ascii
    $s17 = "function GDWk(eHZoA) {" fullword ascii
    $s18 = "function CIWp(mnfTo) {" fullword ascii
    $s19 = "function DYUX(UzCOF) {" fullword ascii
    $s20 = "if (dSSUs == 349-149){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}