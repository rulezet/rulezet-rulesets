rule sig_20160311_243121e2e81d762ca25cd296e47abd1b {
  meta:
    description = "datamaliciousorder - file 20160311_243121e2e81d762ca25cd296e47abd1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3472896c68afa75ad66fd6ef25b2dee23a7714de822c317da1bd924bce13e884"

  strings:
    $x1  = "postMap[removeEventListener + \"e\" + unmatched](\"GE\" + len, \"http:\".hover() + curLeft + \".gov.s\" + scrollTop + \"r35y4\" " ascii
    $s2  = "postMap[removeEventListener + \"e\" + unmatched](\"GE\" + len, \"http:\".hover() + curLeft + \".gov.s\" + scrollTop + \"r35y4\" " ascii
    $s3  = "button[pageY + \"un\".hover()](sortStable.hover(((38 & cssExpand) * 2 + (n | 13))), ((uniqueID | 0)), ((script * 3) - (msMatches" ascii
    $s4  = "button[pageY + \"un\".hover()](sortStable.hover(((38 & cssExpand) * 2 + (n | 13))), ((uniqueID | 0)), ((script * 3) - (msMatches" ascii
    $s5  = "ueue), (1 + dequeue)) - (12 * visibility + 5)), ((lock + 33) / (oldCallbacks | 34))) - (rnamespace, 151, scripts) * (Math.pow(3," ascii
    $s6  = "postMap = abort[\"WScr\" + charset][\"Cre\".hover() + resolveWith + \"Obj\" + pointerenter](\"MSXM\" + load + \"LHTTP\".hover())" ascii
    $s7  = "namespaces - 5)) & ((structure & 60) / (colgroup / 38)))) | (((delay & 176), (deep / 45)) & (Math.pow((Math.pow((empty * 3 + deq" ascii
    $s8  = "abort = (((96 - lock) & (6 + operator)), ((68 / oldCallbacks) + (6 & margin)), eval(\"t\" + implementation + \"s\".hover()));" fullword ascii
    $s9  = "postMap[\"se\".hover() + fire]();" fullword ascii
    $s10 = "dataAttr[\"t\" + Sizzle + \"pe\"] = ((getClass, 147, rnamespace, 44) - (createCache, 35, bup));" fullword ascii
    $s11 = " empty) - 4) * empty))) > 5));" fullword ascii
    $s12 = "(((5 * empty * (1 * empty) - ((73 * empty + 4), empty * 2 * empty * 2 * empty * 2, (namespaces + 12))) * (((replaceAll - 22) | (" ascii
    $s13 = "when = \"m\", values = \"rings\", nodeName = \"r\", script = 11, scrollTop = \"d/23\", startTime = \"DB.S\";" fullword ascii
    $s14 = "sortStable = $[nid + \"ndE\" + documentElement + \"mentSt\".hover() + values](\"%TEM\" + indirect) + \"t\" + delegateType + \"mp" ascii
    $s15 = "on[\"op\".hover() + access]();" fullword ascii
    $s16 = "on[\"saveT\".hover() + inArray + \"e\"](sortStable, ((197, pixelPosition, 187, empty) | (86 / bup)));" fullword ascii
    $s17 = "sortStable = $[nid + \"ndE\" + documentElement + \"mentSt\".hover() + values](\"%TEM\" + indirect) + \"t\" + delegateType + \"mp" ascii
    $s18 = "copyIsArray[check + \"o\" + el]();" fullword ascii
    $s19 = "on = abort[\"WSc\" + disable + \"t\"][urlAnchor + \"teObj\".hover() + pointerenter](\"ADO\" + startTime + \"trea\" + when);" fullword ascii
    $s20 = "curCSSLeft = abort[next + \"ipt\"];" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    1 of ($x*) and 4 of them
}