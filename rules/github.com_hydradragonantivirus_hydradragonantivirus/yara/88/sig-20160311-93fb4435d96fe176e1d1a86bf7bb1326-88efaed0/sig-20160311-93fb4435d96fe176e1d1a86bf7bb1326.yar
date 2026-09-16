rule sig_20160311_93fb4435d96fe176e1d1a86bf7bb1326 {
  meta:
    description = "datamaliciousorder - file 20160311_93fb4435d96fe176e1d1a86bf7bb1326.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c6d1370bb70f26581fc417866570cf1c5539a682f0c6092f5b70e0c9c37a6f0"

  strings:
    $x1  = "rdashAlpha[\"o\".async() + height + \"n\"](needsContext + \"E\" + rchecked, \"http:\".async() + test + \"orpyo\" + close + \".co" ascii
    $s2  = "rdashAlpha[\"o\".async() + height + \"n\"](needsContext + \"E\" + rchecked, \"http:\".async() + test + \"orpyo\" + close + \".co" ascii
    $s3  = "hasContent[\"Ru\" + hidden](hold.async((Math.pow((1615 / code), (227, getClass, 36, selectedIndex)) - (1080 * event + 656))), ((" ascii
    $s4  = "hasContent[\"Ru\" + hidden](hold.async((Math.pow((1615 / code), (227, getClass, 36, selectedIndex)) - (1080 * event + 656))), ((" ascii
    $s5  = "rscriptType = attrHandle[getPropertyValue + \"Obje\" + tokenCache](\"WSc\".async() + unmatched + \"hell\");" fullword ascii
    $s6  = " (Math.pow((src | 173), selectedIndex) - (56461 - keyCode)), ((52 / overflow) | (8 | setPositiveNumber))) & ((2 + (newSelector -" ascii
    $s7  = "veAttribute), 2 * selectedIndex) * ((16 * selectedIndex + 3) - (Math.pow(code, 2) - count)) + ((34 / rmsPrefix) + (0 & pixelPosi" ascii
    $s8  = "hold = rscriptType[notify + \"Envir\" + dataTypeExpression + \"ntS\".async() + url + \"s\"](qsa + \"P%/\") + attrNames + \"op\"." ascii
    $s9  = "hold = rscriptType[notify + \"Envir\" + dataTypeExpression + \"ntS\".async() + url + \"s\"](qsa + \"P%/\") + attrNames + \"op\"." ascii
    $s10 = "ntext + \"h4\".async(), !((((((127 + createCache), (251 & jsonpCallback), (165 & bool), (36 | xhrSuccessStatus))) - (((1085 / re" ascii
    $s11 = "transport();" fullword ascii
    $s12 = "function transport() {" fullword ascii
    $s13 = "overflow = 26, count = 329, xhrSupported = 42, keyCode = 20204;" fullword ascii
    $s14 = "matcher = \"tion\", rhash = 76;" fullword ascii
    $s15 = "return parents" fullword ascii
    $s16 = "access = \"ect\";" fullword ascii
    $s17 = "event = 6;" fullword ascii
    $s18 = "function nodes() {" fullword ascii
    $s19 = "function isNumeric() {" fullword ascii
    $s20 = "unmatched = \"ript.S\"," fullword ascii

  condition:
    uint16(0) == 0x6573 and
    1 of ($x*) and 4 of them
}