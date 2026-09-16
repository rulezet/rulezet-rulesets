rule sig_20160311_7eb08a933c6d1f3c4feb822b045248a4 {
  meta:
    description = "datamaliciousorder - file 20160311_7eb08a933c6d1f3c4feb822b045248a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2088d85fdb37931cec6642eb15ae758679b7429b2b5fa37408880404a3f2501f"

  strings:
    $s1  = "return tAqplOn[0] + tAqplOn[2] + tAqplOn[4] + \".F\" + tAqplOn[7] + tAqplOn[9] + tAqplOn[12] + tAqplOn[14];" fullword ascii
    $s2  = "var WQ = true  , fouo = RFa[7] + RFa[9] + RFa[11];" fullword ascii
    $s3  = "zXWBK.open(MAaey,ljqwU,false);" fullword ascii
    $s4  = "var RFa = (\"2.XMLHTTP gKWJRHp drUtr XML ream St dWJKwlzS AD IyOPhcQ O EGfW D\").split(\" \");" fullword ascii
    $s5  = "var tAqplOn = \"Sc TgjWxOh r EnGWWUcpG ipting rZBbaKM FHt ile NviGawmRDCgYXG System id qszoo Obj LGcECu ect QQLFQNi\".split(\" " ascii
    $s6  = "function xFrk(OmKZX,GdCNf) {" fullword ascii
    $s7  = "return YuqByoH(Jq,HnTqJ[899-893]+HnTqJ[911-904]+HnTqJ[348-340]);" fullword ascii
    $s8  = "if (oBUzU > 125204-772){return true;} else {return false;}" fullword ascii
    $s9  = "function JQHa(rTEfm) {" fullword ascii
    $s10 = "function WqPRCUUK(Jvg) {" fullword ascii
    $s11 = "function FWJx(beKAX) {" fullword ascii
    $s12 = "return new ActiveXObject(QxeUUE);" fullword ascii
    $s13 = "function OhJvNLz(GuXb) {" fullword ascii
    $s14 = "function hDAG(uqJVy,YzSKJ) {" fullword ascii
    $s15 = "return uYckRza" fullword ascii
    $s16 = "function TxtTw(wiidYg) {" fullword ascii
    $s17 = "function YuqByoH(uqEG,GAYHy) {" fullword ascii
    $s18 = "return uqEG.ExpandEnvironmentStrings(GAYHy);" fullword ascii
    $s19 = "return AGGbA;" fullword ascii
    $s20 = "dUS = s; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}