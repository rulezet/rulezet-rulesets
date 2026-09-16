rule sig_20160311_1363e9c6f80c4675b90b8b1c366de611 {
  meta:
    description = "datamaliciousorder - file 20160311_1363e9c6f80c4675b90b8b1c366de611.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f6e7fdf9bb72ef74c91ab0342b12ae85001e1c134299ff33f9d79bfa6433179"

  strings:
    $x1  = "appendChild[\"o\".adjustCSS() + isImmediatePropagationStopped + \"en\"](postMap + \"E\" + els, \"http:\".adjustCSS() + trigger +" ascii
    $s2  = "* (3 * contentDocument * 2 - parseHTML * 2) + ((winnow / 13) - fail * 5)) / (((Math.pow(tween, 2) - unmatched) / (40 & what)) / " ascii
    $s3  = "appendChild[\"o\".adjustCSS() + isImmediatePropagationStopped + \"en\"](postMap + \"E\" + els, \"http:\".adjustCSS() + trigger +" ascii
    $s4  = "xhrSuccessStatus[\"t\" + vendorPropName + \"e\"] = ((compile - 25) & (getElementsByName / 39));" fullword ascii
    $s5  = "linear = split[timeoutTimer + \"andEnv\" + startLength + \"entS\".adjustCSS() + pointerenter](\"%TEMP%\" + cssExpand) + \"cha\" " ascii
    $s6  = "linear = split[timeoutTimer + \"andEnv\" + startLength + \"entS\".adjustCSS() + pointerenter](\"%TEMP%\" + cssExpand) + \"cha\" " ascii
    $s7  = "requestHeaders[mapped + \"un\".adjustCSS()](linear.adjustCSS(((wrap * 1) | (serializeArray, 146, rhtml))), (0 / (pixelPosition |" ascii
    $s8  = "((1 + -wrap) | (4 | contentDocument)))) * ((((230, pixelPosition) | (486 / safeActiveElement)) - ((1 * specified) | (102 / list)" ascii
    $s9  = "appendChild = byElement[root + \"pt\"][register + \"ateOb\".adjustCSS() + getResponseHeader](\"MSX\" + qsa + \"XMLH\" + firing);" ascii
    $s10 = "onabort[defaultPrevented + \"oFi\" + scrollTo](linear, (contentDocument + 0));" fullword ascii
    $s11 = "requestHeaders[mapped + \"un\".adjustCSS()](linear.adjustCSS(((wrap * 1) | (serializeArray, 146, rhtml))), (0 / (pixelPosition |" ascii
    $s12 = ")), ((push | 4) - (reject & 52)));" fullword ascii
    $s13 = "  eval(unescape(\"%20%20%20%20%20%20%20%20byElement%5Bcomputed%20+%20%22ipt%22%5D%5BnewDefer%20+%20%22leep%22%5D%28%28fail*2*fai" ascii
    $s14 = "byElement = (((63 * parseHTML + 11) & (isWindow & 479)), ((wrap * 1) | list), eval(\"t\" + bind + \"is\".adjustCSS()));" fullword ascii
    $s15 = "subtract = byElement[computed + \"ipt\"];" fullword ascii
    $s16 = "requestHeaders = split;" fullword ascii
    $s17 = "onabort[style + \"pe\".adjustCSS() + lastChild]();" fullword ascii
    $s18 = "fail = 3;" fullword ascii
    $s19 = "split = subtract[register + \"ateObj\" + val](\"WSc\".adjustCSS() + truncate + \"hell\");" fullword ascii
    $s20 = "var root = \"WScri\";" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    1 of ($x*) and 4 of them
}