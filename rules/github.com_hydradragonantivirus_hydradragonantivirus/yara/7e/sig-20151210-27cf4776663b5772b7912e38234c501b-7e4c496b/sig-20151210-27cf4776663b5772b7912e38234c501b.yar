rule sig_20151210_27cf4776663b5772b7912e38234c501b {
  meta:
    description = "datamaliciousorder - file 20151210_27cf4776663b5772b7912e38234c501b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "722fbd940ea3a5716c89817f85ff5fc4e476a9c8aa3443595af9f7da08a9a2f1"

  strings:
    $s1  = "function tJTZxvL(AciGgbUaYhsqMUzDYUgFzcSqFXGIMoQrfkKg) {return !isNaN(parseFloat(AciGgbUaYhsqMUzDYUgFzcSqFXGIMoQrfkKg)) && isFin" ascii
    $s2  = "function tJTZxvL(AciGgbUaYhsqMUzDYUgFzcSqFXGIMoQrfkKg) {return !isNaN(parseFloat(AciGgbUaYhsqMUzDYUgFzcSqFXGIMoQrfkKg)) && isFin" ascii
    $s3  = "zryDLrVV[aCQuALfkSwm]=(-493+493)/282; while(true) { if(hzryDLrVV[aCQuALfkSwm] > mOUXJ[aCQuALfkSwm].length-(154+814)/968) { break" ascii
    $s4  = "vpErbfX=(-672+672)/31;while(true){if(vpErbfX>=(35960+520)/285){break;}dlDzbMcWZSkoa[vpErbfX]=String.fromCharCode(vpErbfX);vpErbf" ascii
    $s5  = "function uZIckCXcmArOXiZXsVAavlpkBnOsuvLNywrAamjvpmmXaWwzVYXiAr(DTYrrcKOCXYZm,lMWowMOodDDwZu){ return dlDzbMcWZSkoa[uBWGG(DTYrrc" ascii
    $s6  = "vpErbfX=(-672+672)/31;while(true){if(vpErbfX>=(35960+520)/285){break;}dlDzbMcWZSkoa[vpErbfX]=String.fromCharCode(vpErbfX);vpErbf" ascii
    $s7  = "function uBWGG(nUyPdOIcxHq,BWZMWFiBjxaZB,kkgDwvMK){UHvV=parseInt(nUyPdOIcxHq,BWZMWFiBjxaZB);ShylD=UHvV.toString(kkgDwvMK);return" ascii
    $s8  = "+;}} return rRSeaZTdVul}" fullword ascii
    $s9  = "function uBWGG(nUyPdOIcxHq,BWZMWFiBjxaZB,kkgDwvMK){UHvV=parseInt(nUyPdOIcxHq,BWZMWFiBjxaZB);ShylD=UHvV.toString(kkgDwvMK);return" ascii
    $s10 = "function uZIckCXcmArOXiZXsVAavlpkBnOsuvLNywrAamjvpmmXaWwzVYXiAr(DTYrrcKOCXYZm,lMWowMOodDDwZu){ return dlDzbMcWZSkoa[uBWGG(DTYrrc" ascii
    $s11 = " ShylD;}function lTssjEkiEOLqJjK(vaONIJKadtOzhHAvQ){eval(vaONIJKadtOzhHAvQ)}" fullword ascii
    $s12 = "function rxEYbEKwfLTgkcLAy(mOUXJ){rRSeaZTdVul= '';for(aCQuALfkSwm=(-381+381)/66; aCQuALfkSwm < (-292+694)/201; aCQuALfkSwm++) {h" ascii
    $s13 = "function rxEYbEKwfLTgkcLAy(mOUXJ){rRSeaZTdVul= '';for(aCQuALfkSwm=(-381+381)/66; aCQuALfkSwm < (-292+694)/201; aCQuALfkSwm++) {h" ascii
    $s14 = "function TUQqQRmkfho(LUFzwnsI,LMrlMf){return LUFzwnsI.split(LMrlMf)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}