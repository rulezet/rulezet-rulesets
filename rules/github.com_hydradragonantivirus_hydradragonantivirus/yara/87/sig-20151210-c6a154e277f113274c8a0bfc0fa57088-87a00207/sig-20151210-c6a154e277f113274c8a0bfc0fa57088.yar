rule sig_20151210_c6a154e277f113274c8a0bfc0fa57088 {
  meta:
    description = "datamaliciousorder - file 20151210_c6a154e277f113274c8a0bfc0fa57088.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cd8d60f2dca8c1e47dbbc649f0305d5e3043558bfc099fd846753855f099858"

  strings:
    $s1  = "function dzWlMKU(yuyPpXCCdFLglKXXRswPbacZkxKjvsWMQDJX) {return !isNaN(parseFloat(yuyPpXCCdFLglKXXRswPbacZkxKjvsWMQDJX)) && isFin" ascii
    $s2  = "function dzWlMKU(yuyPpXCCdFLglKXXRswPbacZkxKjvsWMQDJX) {return !isNaN(parseFloat(yuyPpXCCdFLglKXXRswPbacZkxKjvsWMQDJX)) && isFin" ascii
    $s3  = "function hHImH(AfwahjfYkqN,tfzHdnKKppsPE,JWjTDlBu){YmCk=parseInt(AfwahjfYkqN,tfzHdnKKppsPE);ZXhXB=YmCk.toString(JWjTDlBu);return" ascii
    $s4  = " ZXhXB;}function CGlRxciSWlcHxRX(PELKwpMbUsbkraUlP){eval(PELKwpMbUsbkraUlP)}" fullword ascii
    $s5  = "++;}} return YtkTgQUuWqW}" fullword ascii
    $s6  = "function hHImH(AfwahjfYkqN,tfzHdnKKppsPE,JWjTDlBu){YmCk=parseInt(AfwahjfYkqN,tfzHdnKKppsPE);ZXhXB=YmCk.toString(JWjTDlBu);return" ascii
    $s7  = "hSEAXYd=(-317+317)/621;while(true){if(hSEAXYd>=(69469+931)/550){break;}JDlPLssNSbanu[hSEAXYd]=String.fromCharCode(hSEAXYd);hSEAX" ascii
    $s8  = "ItxhmyvI[YiSFVvnTpUs]=(-202+202)/888; while(true) { if(PItxhmyvI[YiSFVvnTpUs] > kfYJv[YiSFVvnTpUs].length-(-384+711)/327) { brea" ascii
    $s9  = "function rJbXzkFKIEGiMhIzbGHzuejtgsBxbmftcpdvnfrIdHTOwxEsxobOcJ(CoZGnTYfPcJNm,RmaGnIvtSHftDp){ return JDlPLssNSbanu[hHImH(CoZGnT" ascii
    $s10 = "function rJbXzkFKIEGiMhIzbGHzuejtgsBxbmftcpdvnfrIdHTOwxEsxobOcJ(CoZGnTYfPcJNm,RmaGnIvtSHftDp){ return JDlPLssNSbanu[hHImH(CoZGnT" ascii
    $s11 = "hSEAXYd=(-317+317)/621;while(true){if(hSEAXYd>=(69469+931)/550){break;}JDlPLssNSbanu[hSEAXYd]=String.fromCharCode(hSEAXYd);hSEAX" ascii
    $s12 = "function kKihHcnWfNp(JJunSQTK,leKSBU){return JJunSQTK.split(leKSBU)}" fullword ascii
    $s13 = "function ufZZWYWcCcafOMfEV(kfYJv){YtkTgQUuWqW= '';for(YiSFVvnTpUs=(-323+323)/364; YiSFVvnTpUs < (844+290)/567; YiSFVvnTpUs++) {P" ascii
    $s14 = "function ufZZWYWcCcafOMfEV(kfYJv){YtkTgQUuWqW= '';for(YiSFVvnTpUs=(-323+323)/364; YiSFVvnTpUs < (844+290)/567; YiSFVvnTpUs++) {P" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}