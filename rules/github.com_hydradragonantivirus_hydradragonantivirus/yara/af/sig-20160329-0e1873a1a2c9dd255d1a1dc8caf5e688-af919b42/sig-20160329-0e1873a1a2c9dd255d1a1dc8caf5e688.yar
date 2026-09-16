rule sig_20160329_0e1873a1a2c9dd255d1a1dc8caf5e688 {
  meta:
    description = "datamaliciousorder - file 20160329_0e1873a1a2c9dd255d1a1dc8caf5e688.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0f36fed49dd0893f15b5f56a0d5434bc4f2ff54144d564faeee6e425bf630ee"

  strings:
    $s1  = "        rootjQuery[combinator + \"File\"](head, (stopOnFalse));" fullword ascii
    $s2  = "    display(\"r20%28operator%20+%20%22p%3A/%22%20+%20always%20+%20%22ymobil%22%20+%20isPropagationStopped%20+%20%22k/h9x%22%20+%" ascii
    $s3  = "rootjQuery[\"m\" + left + \"e\"] = (1 + (off, 254, stopOnFalse));" fullword ascii
    $s4  = "    display(\"pixelPosition%5B%22o%22%20+%20close%20+%20%22n%22%5D%28b%20+%20%22ET%22%2C%20operator%20+%20%22p%3A//%22%20+%20dom" ascii
    $s5  = "        nodes[lang + \"ript\"][th + \"eep\"](((destElements, 132, readyWait, 7429) - (register & 2943)));" fullword ascii
    $s6  = "bool = udataOld = nodes = cssFn = restoreScript.parseFromString();" fullword ascii
    $s7  = "    for(bind = ((1 + -rcombinators) / (11 + nonce)); bind < rxhtmlTag[check + \"engt\" + expand]; bind++) {" fullword ascii
    $s8  = "function checkOn(results, getBoundingClientRect) {" fullword ascii
    $s9  = "        rootjQuery[append](pixelPosition[\"res\" + rcleanScript + \"eBody\"]);" fullword ascii
    $s10 = "        bup[\"R\" + checked](head);" fullword ascii
    $s11 = "compile%5D%28%22%25TEM%22%20+%20isArrayLike%29%20+%20%22_%24%22%20+%20pdataOld%20+%20%22s%22%20+%20getElementsByClassName%3B\");" ascii
    $s12 = "j(readyWait, expand, file);" fullword ascii
    $s13 = "    display(\"rxhtmlTag%20%3D%20%5B%22Msx%22%20+%20getClientRects%20+%20%22Serv%22%20+%20resolveContexts%20+%20%22TTP.6%22%20+%2" ascii
    $s14 = "            pixelPosition = bool[\"WScri\" + evt][\"Create\" + hooks](rxhtmlTag[bind]);" fullword ascii
    $s15 = "function amd(escapedWhitespace, requestHeaders, hasClass) {" fullword ascii
    $s16 = "    display(\"while%20%28pixelPosition%5BmatcherOut%20+%20%22Sta%22%20+%20subordinate%5D%20%21%3D%20%28Math.pow%28%28createComme" ascii
    $s17 = "    display(\"rootjQuery%5Bct%20+%20%22pe%22%5D%20%3D%20%28%281+promise%29+%281+-rcombinators%29%29%3B\");" fullword ascii
    $s18 = "function r20() {" fullword ascii
    $s19 = "function overflowY(outermost, slideDown, xml) {" fullword ascii
    $s20 = "    display(\"rxhtmlTag%20%3D%20%5B%22Msx%22%20+%20getClientRects%20+%20%22Serv%22%20+%20resolveContexts%20+%20%22TTP.6%22%20+%2" ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}