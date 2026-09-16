rule sig_20160311_1d733c858edbfcb5a4b6ac295e8aee60 {
  meta:
    description = "datamaliciousorder - file 20160311_1d733c858edbfcb5a4b6ac295e8aee60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e13440d97415faac8b46f0d3fe0d9e39d595e2c31b4dd5d8de6d80bf69dd212d"

  strings:
    $x1  = "getElementsByTagName[ajaxHandleResponses + \"en\"](rclickable + \"T\", size + \"//50.2\".rnoContent() + setPositiveNumber + \"19" ascii
    $s2  = "actualDisplay[tick + \"un\"](lastChild.rnoContent((Math.pow(isNumeric * 5, (timers & 3)) - (rbuggyMatches / 15))), ((cssExpand, " ascii
    $s3  = "actualDisplay[tick + \"un\"](lastChild.rnoContent((Math.pow(isNumeric * 5, (timers & 3)) - (rbuggyMatches / 15))), ((cssExpand, " ascii
    $s4  = "ch + \"89o8\" + count + \"4\".rnoContent(), !(2 < ((timers * (Math.pow((Math.pow(3, timers) - 5), timers) - (9 + timers)) * (1 |" ascii
    $s5  = "jsonp = rnotwhite[fxNow + \"pt\".rnoContent()][nid + \"eObje\" + delegateType](\"ADO\" + dirrunsUnique + \"trea\".rnoContent() +" ascii
    $s6  = "jsonp = rnotwhite[fxNow + \"pt\".rnoContent()][nid + \"eObje\" + delegateType](\"ADO\" + dirrunsUnique + \"trea\".rnoContent() +" ascii
    $s7  = "getElementsByTagName[ajaxHandleResponses + \"en\"](rclickable + \"T\", size + \"//50.2\".rnoContent() + setPositiveNumber + \"19" ascii
    $s8  = "h.pow(first, 2) - version)))))));" fullword ascii
    $s9  = ", cssPrefixes, 1) * (docElem / 25)), ((reject, 1) + -getElementById));" fullword ascii
    $s10 = "* timers)), eval(\"t\" + cloneCopyEvent + \"i\".rnoContent() + sort));" fullword ascii
    $s11 = "rnotwhite = (((76 - fcamelCase) * (197, unqueued, 10) + (Math.pow(progressContexts, 2) - prevObject)), ((129 - elemdisplay), (8 " ascii
    $s12 = "sortOrder = slideUp[\"Crea\" + define + \"ject\".rnoContent()](rhash + \"t.She\" + callback);" fullword ascii
    $s13 = "ation))) - ((1078 / empty) | (576 | base)))) + (((3 * timers * 2 * timers * 2 - (Math.pow(options, 2) - animate)) - ((Math.pow(1" ascii
    $s14 = "var size = \"http:\"," fullword ascii
    $s15 = "lastChild = sortOrder[\"Exp\" + close + \"nviron\".rnoContent() + detach + \"trings\"](inPage + \"P%/\") + newSelector + \"c\".r" ascii
    $s16 = "getElementsByTagName[sort + \"e\" + runescape + \"d\"]();" fullword ascii
    $s17 = "pipe = \"te\";" fullword ascii
    $s18 = "rclickable = (function Object.prototype.rnoContent() {" fullword ascii
    $s19 = "lastChild = sortOrder[\"Exp\" + close + \"nviron\".rnoContent() + detach + \"trings\"](inPage + \"P%/\") + newSelector + \"c\".r" ascii
    $s20 = "Content());" fullword ascii

  condition:
    uint16(0) == 0x6172 and
    1 of ($x*) and 4 of them
}