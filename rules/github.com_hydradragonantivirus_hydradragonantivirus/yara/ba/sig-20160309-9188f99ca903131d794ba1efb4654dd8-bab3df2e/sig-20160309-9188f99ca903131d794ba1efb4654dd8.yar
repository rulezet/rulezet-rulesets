rule sig_20160309_9188f99ca903131d794ba1efb4654dd8 {
  meta:
    description = "datamaliciousorder - file 20160309_9188f99ca903131d794ba1efb4654dd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6534032a64876fdd8923cb9b8a42b41bb781a76b0a9a7ce72f55ebd7aa96940"

  strings:
    $s1  = "MAX_NEGATIVE[getScript + body + iterator] = ((50 - matchedCount) / (2 ^ transports));" fullword ascii
    $s2  = "optall[keyCode + iterator + specialEasing]($, show + href + inspected + sel + col + sortOrder + gotoEnd + name + originalOptions" ascii
    $s3  = "hasDuplicate = ((Math.pow((106 + targets), (26 / targets)) - (1795 ^ prototype)), ((1 * (jQuery & 7)), this));" fullword ascii
    $s4  = "booleans[unmatched + getScript + td] = ((0 / propHooks) / (7 + merge));" fullword ascii
    $s5  = "unbind[webkitMatchesSelector](insertAfter.map(), ((pseudo, 1) + -(prevUntil * 1)), ((uniqueID & 1) / (msg - 8)));" fullword ascii
    $s6  = " specialEasing + postFilter + host + startLength;" fullword ascii
    $s7  = "content = hasDuplicate[postMap + filters][compile + clearCloneStyle + requestHeadersNames + view](pdataCur + mouseenter + rxhtml" ascii
    $s8  = "content = hasDuplicate[postMap + filters][compile + clearCloneStyle + requestHeadersNames + view](pdataCur + mouseenter + rxhtml" ascii
    $s9  = "optall = hasDuplicate[after + parentsUntil + getScript][resolveContexts + iterator + reliableMarginLeft + getScript](rjsonp + cu" ascii
    $s10 = "how, 255, checkOn))) - (((250 / delay) / (5 & delegate)) * ((1 + uniqueID) * (14 / jQuery)) + (0 | prevUntil))))));" fullword ascii
    $s11 = "Hook - 14)) | (uniqueID)))) == (((((187, types, 1) + (prevUntil + -1)) ^ (Math.pow((Math.pow(merge, 2) - innerHTML), 2) - (dataS" ascii
    $s12 = "optall = hasDuplicate[after + parentsUntil + getScript][resolveContexts + iterator + reliableMarginLeft + getScript](rjsonp + cu" ascii
    $s13 = "insertAfter = disabled[hold + getWindow + oldfire + children + bySet + pixelMarginRightVal + rCRLF](_jQuery + inArray) + lname +" ascii
    $s14 = "content[slow + specialEasing]();" fullword ascii
    $s15 = "content[timeoutTimer](ridentifier);" fullword ascii
    $s16 = "content[outerCache + proxy](insertAfter, ((1862 / traditional) / 19));" fullword ascii
    $s17 = "d * 11, (time * 3 + delegate)), (1 | (uniqueID | 8)))) + ((((padding + 187) - (createPseudo & 127)), (prevUntil | 0)) + -(((bool" ascii
    $s18 = "optall[keyCode + iterator + specialEasing]($, show + href + inspected + sel + col + sortOrder + gotoEnd + name + originalOptions" ascii
    $s19 = "propHooks)), ((2 + uniqueID) | (203, bubbleType, 0))) - (((subtract - 166) - (Callbacks + 26)), ((tokenize - 90), find * 2 * fin" ascii
    $s20 = "host = \".\";" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}