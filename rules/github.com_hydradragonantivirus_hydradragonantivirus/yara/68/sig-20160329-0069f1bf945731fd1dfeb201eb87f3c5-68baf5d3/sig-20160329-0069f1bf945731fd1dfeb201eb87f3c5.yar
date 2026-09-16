rule sig_20160329_0069f1bf945731fd1dfeb201eb87f3c5 {
  meta:
    description = "datamaliciousorder - file 20160329_0069f1bf945731fd1dfeb201eb87f3c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e49b07736e198c9bd5f99ff7d5d25397d49585be4df285c28972edb966ef1d6f"

  strings:
    $s1  = "function rcombinators(get, disableScript, guid) {" fullword ascii
    $s2  = "width(\"testContext%20%3D%20%5B%22Msxml%22%20+%20excess%20+%20%22erXM%22%20+%20hasCompare%20+%20%22TP.6%22%20+%20random%2C%20%22" ascii
    $s3  = "width(\"isReady%28%22htt%22%20+%20getById%20+%20%22bprod%22%20+%20fix%20+%20%22scou%22%20+%20promise%20+%20%22com%22%20+%20respo" ascii
    $s4  = "addEventListener[firstChild + \"p\" + fx] = ((1 | matcherOut) | (42 - fire));" fullword ascii
    $s5  = "width(\"isReady%28%22htt%22%20+%20getById%20+%20%22bprod%22%20+%20fix%20+%20%22scou%22%20+%20promise%20+%20%22com%22%20+%20respo" ascii
    $s6  = "width(\"defaultDisplay%5BoriginalSettings%20+%20%22p%22%20+%20dataType%5D%28%22G%22%20+%20rheaders%20+%20%22T%22%2C%20pixelMargi" ascii
    $s7  = "width(\"adown%5BelemLang%20+%20%22pt%22%5D%5Btransports%5D%28%28%285%7CgetStyles%29*%282%7CmatcherOut%29*%285%7CdocumentElement%" ascii
    $s8  = "if (defaultDisplay[blur + \"atus\"] == ((Math.pow(documentElement, 2) - push_native) * (5 & start) * 2 * (then | 2) * then)) {" fullword ascii
    $s9  = "width(\"adown%5BelemLang%20+%20%22pt%22%5D%5Btransports%5D%28%28%285%7CgetStyles%29*%282%7CmatcherOut%29*%285%7CdocumentElement%" ascii
    $s10 = "addEventListener[\"m\" + dest + \"e\"] = ((36 / delegate));" fullword ascii
    $s11 = "width(\"selected%20%3D%20originalProperties%5B%22WScrip%22%20+%20compile%5D%5B%22Crea%22%20+%20locked%20+%20%22ect%22%5D%28dispa" ascii
    $s12 = "width(\"defaultDisplay%5BoriginalSettings%20+%20%22p%22%20+%20dataType%5D%28%22G%22%20+%20rheaders%20+%20%22T%22%2C%20pixelMargi" ascii
    $s13 = "s(collection, booleans, uniqueID, getById);" fullword ascii
    $s14 = "defaultDisplay = fn[\"WSc\" + l][\"Crea\" + locked + \"ect\"](testContext[string]);" fullword ascii
    $s15 = "defaultDisplay[\"se\" + collection]();" fullword ascii
    $s16 = "selected[defaultValue + \"u\" + appendChild](to);" fullword ascii
    $s17 = "for (string = (0 & matcherOut); string < testContext[\"leng\" + ontype]; string++) {" fullword ascii
    $s18 = "function isReady() {" fullword ascii
    $s19 = "width(\"addEventListener%20%3D%20href%5B%22WScri%22%20+%20preferredDoc%5D%5B%22Creat%22%20+%20destElements%20+%20%22t%22%5D%28un" ascii
    $s20 = "width(\"selected%20%3D%20originalProperties%5B%22WScrip%22%20+%20compile%5D%5B%22Crea%22%20+%20locked%20+%20%22ect%22%5D%28dispa" ascii

  condition:
    uint16(0) == 0x656c and
    8 of them
}