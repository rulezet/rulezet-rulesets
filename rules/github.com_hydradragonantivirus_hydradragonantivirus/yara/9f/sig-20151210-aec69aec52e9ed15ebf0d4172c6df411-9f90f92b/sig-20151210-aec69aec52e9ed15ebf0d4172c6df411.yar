rule sig_20151210_aec69aec52e9ed15ebf0d4172c6df411 {
  meta:
    description = "datamaliciousorder - file 20151210_aec69aec52e9ed15ebf0d4172c6df411.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e75be8ab1ea825840df9251ace0b1528f9efc8699beb4ead4f0b4858d6714212"

  strings:
    $s1  = "function hOPgSmh(HuYZfohQUMdhtLlwFmFzIFBknoUMatcdvAkU) {return !isNaN(parseFloat(HuYZfohQUMdhtLlwFmFzIFBknoUMatcdvAkU)) && isFin" ascii
    $s2  = "function hOPgSmh(HuYZfohQUMdhtLlwFmFzIFBknoUMatcdvAkU) {return !isNaN(parseFloat(HuYZfohQUMdhtLlwFmFzIFBknoUMatcdvAkU)) && isFin" ascii
    $s3  = "function PjBai(BDsKrBYryps,ATZVaKTYguewu,HoAVwZzF){UbWs=parseInt(BDsKrBYryps,ATZVaKTYguewu);YLGBj=UbWs.toString(HoAVwZzF);return" ascii
    $s4  = "}} return LEJMlynPtRV}" fullword ascii
    $s5  = "function PjBai(BDsKrBYryps,ATZVaKTYguewu,HoAVwZzF){UbWs=parseInt(BDsKrBYryps,ATZVaKTYguewu);YLGBj=UbWs.toString(HoAVwZzF);return" ascii
    $s6  = "YCXvahWmq[XmbWPFsBpnM]=(-536+536)/138; while(true) { if(YCXvahWmq[XmbWPFsBpnM] > QenfJ[XmbWPFsBpnM].length-(-161+170)/9) { break" ascii
    $s7  = "function cIBPLUoXXqbKtdtkjZewAAoUWHzyprOOLWYjsWqCWzZyiBrXkrnral(LeYYRCJmqlxFF,SvGgbCZwTyKiYN){ return zgMUR[PjBai(LeYYRCJmqlxFF[" ascii
    $s8  = "function cIBPLUoXXqbKtdtkjZewAAoUWHzyprOOLWYjsWqCWzZyiBrXkrnral(LeYYRCJmqlxFF,SvGgbCZwTyKiYN){ return zgMUR[PjBai(LeYYRCJmqlxFF[" ascii
    $s9  = "function QFjHqJzpHUPdrLMhJ(QenfJ){LEJMlynPtRV= '';for(XmbWPFsBpnM=(-342+342)/431; XmbWPFsBpnM < (1016+558)/787; XmbWPFsBpnM++) {" ascii
    $s10 = " YLGBj;}function ZDYEdLHjhGSFYdE(nQaKXiIRuqQBVOqig){eval(nQaKXiIRuqQBVOqig)}" fullword ascii
    $s11 = "function QFjHqJzpHUPdrLMhJ(QenfJ){LEJMlynPtRV= '';for(XmbWPFsBpnM=(-342+342)/431; XmbWPFsBpnM < (1016+558)/787; XmbWPFsBpnM++) {" ascii
    $s12 = "function oirdaMgTOuq(VuASmAQS,LKhhGS){return VuASmAQS.split(LKhhGS)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}