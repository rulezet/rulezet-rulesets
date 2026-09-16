rule sig_20160325_e5cb8961688412ad10ffd480d0918694 {
  meta:
    description = "datamaliciousorder - file 20160325_e5cb8961688412ad10ffd480d0918694.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8823e8ebf107503c67e7484affe7169b10583efa12298067fb80e592bb3a91e2"

  strings:
    $s1  = "pattern[doneName](((emptyGet, 253, height) - (216 + requestHeaders)));" fullword ascii
    $s2  = "triggered(temp, cleanData, requestHeaders, mouseleave);" fullword ascii
    $s3  = "getWidthOrHeight(cleanData, mouseleave, temp);" fullword ascii
    $s4  = "var location = [][\"const\" + temp + \"r\"][rlocalProtocol + \"otyp\" + step][\"so\" + rnoInnerhtml][\"appl\" + max]();" fullword ascii
    $s5  = "getAll = \"om/5\", firstDataType = \"TP.6.\", proxy = 8;" fullword ascii
    $s6  = "createComment[cleanData + \"p\" + step] = ((1 + rwhitespace) & 1);" fullword ascii
    $s7  = "flag = \"%TEMP\";" fullword ascii
    $s8  = "temp = \"ructo\";" fullword ascii
    $s9  = "ajaxTransport[\"s\" + load + \"d\"]();" fullword ascii
    $s10 = "createComment = new close[\"Act\" + tick + \"bjec\" + wrapMap](\"ADOD\" + mouseenter + \"tream\");" fullword ascii
    $s11 = "parentNode = close = createFxNow = queue = remove.computed();" fullword ascii
    $s12 = "stop = (function remove.computed() {" fullword ascii
    $s13 = "function currentValue(rscriptType, handlerQueue, window, createElement) {" fullword ascii
    $s14 = "return handlerQueue[createElement](rscriptType, window);" fullword ascii
    $s15 = "function getWidthOrHeight() {" fullword ascii
    $s16 = "when(_load, tick, rnoInnerhtml, getAll, second);" fullword ascii
    $s17 = "var current = \"getter\"," fullword ascii
    $s18 = "pattern = createFxNow[\"WScr\" + appendTo];" fullword ascii
    $s19 = "qualifier[\"c\" + whitespace]();" fullword ascii
    $s20 = "prepend = div1[display + \"andEn\" + matchExpr + \"onment\" + xml + \"s\"](flag + \"%/\") + current + \".s\" + nid + \"r\";" fullword ascii

  condition:
    uint16(0) == 0x6e72 and
    8 of them
}