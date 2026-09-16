rule sig_20160311_da89f218b51197b50320c64866178e71 {
  meta:
    description = "datamaliciousorder - file 20160311_da89f218b51197b50320c64866178e71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5461464e596bff2415e75e152a48f98310f845aeeb38ffa8150ee9e5bd9ab30"

  strings:
    $s1  = "safeActiveElement[\"op\" + rneedsContext](\"GE\" + sibling, \"http:/\".rtrim() + context + \"my_al\" + rlocalProtocol + \"repu\"" ascii
    $s2  = "* 10 + timer) & (61 & responseType)), (Math.pow(21, current) - 412), (response * 3 * minWidth * 3, (timer * 2))) + (((start + 22" ascii
    $s3  = "bind[identifier + \"y\".rtrim() + empty] = ((31 & noCloneChecked) - (390 / tween));" fullword ascii
    $s4  = "7 / rclass))) | ((((3444 * response + 2142) & (setup - 3008)) / ((getClass / 13), (css + 31), (radio & 55))), (Math.pow((rtypena" ascii
    $s5  = "queue = type[\"Expan\" + fcamelCase + \"ironme\".rtrim() + buildFragment + \"ring\" + Callbacks](\"%TEMP\" + contentDocument) + " ascii
    $s6  = "queue = type[\"Expan\" + fcamelCase + \"ironme\".rtrim() + buildFragment + \"ring\" + Callbacks](\"%TEMP\" + contentDocument) + " ascii
    $s7  = "oValue), (0 | fixInput)), (116, (readyList - 184), (margin + 39), tween), ((176, initial) - (34 | margin)), (31 / noCloneChecked" ascii
    $s8  = "rsingleTag[\"R\" + rquery](queue.rtrim(((4 + tmp), (23 * base + 6), (combinator - 41))), ((etag / 37) + -(timer + 0)), domManip)" ascii
    $s9  = "createInputPseudo[\"sav\" + computed + \"e\".rtrim()](queue, ((reliableMarginRight - 19) / (expanded, 49)));" fullword ascii
    $s10 = "ption, 2) - rmargin), (2414 / interval)), ((217, domManip) | (228, cssFn, 125, domManip))) | (2 + (fontWeight, 0))) / ((((start " ascii
    $s11 = "mespace * 2 + response), (120, originalEvent, 211, current)) - (3672 / interval)) * ((49 / timer) - 2 * preFilter), (((25 + radi" ascii
    $s12 = ") - (string | 25)) + -((origName, 150, unquoted, 0) | timer))))));" fullword ascii
    $s13 = " \"ka.pl\".rtrim() + tfoot + \"7g5\", !((((((tween + 1) / current * 7) | (domManip / (8 | start))) + -((4 | valueIsBorderBox) - " ascii
    $s14 = "div1 = ((352 - (then + 126)), ((timer | 1) * (progress / 6)), eval(\"t\" + firing + \"s\".rtrim()));" fullword ascii
    $s15 = "safeActiveElement = div1[\"WScri\" + locked][\"Cre\".rtrim() + arg + \"Objec\" + identifier](\"MSX\" + setMatcher + \"XMLHT\".rt" ascii
    $s16 = "createInputPseudo = div1[\"WScrip\".rtrim() + identifier][\"Cre\" + arg + \"Obje\" + actualDisplay](\"ADO\".rtrim() + scrollTop " ascii
    $s17 = "createInputPseudo = div1[\"WScrip\".rtrim() + identifier][\"Cre\" + arg + \"Obje\" + actualDisplay](\"ADO\".rtrim() + scrollTop " ascii
    $s18 = "safeActiveElement = div1[\"WScri\" + locked][\"Cre\".rtrim() + arg + \"Objec\" + identifier](\"MSX\" + setMatcher + \"XMLHT\".rt" ascii
    $s19 = "safeActiveElement[\"op\" + rneedsContext](\"GE\" + sibling, \"http:/\".rtrim() + context + \"my_al\" + rlocalProtocol + \"repu\"" ascii
    $s20 = "Expr = \"ipt\", etag = 37, readyList = 429, identifier = \"t\", originalEvent = 209;" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}