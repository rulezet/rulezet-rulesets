rule sig_20160308_9ebc1cd3b86423cfedf1bfc09527b5d8 {
  meta:
    description = "datamaliciousorder - file 20160308_9ebc1cd3b86423cfedf1bfc09527b5d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bde8aa1a4d2c007343b8796f679df9dd5b631f3165e721a84e48171d07e6f96"

  strings:
    $x1  = "obj[split](tabIndex + nodes, clientX + rnamespace + rcleanScript + serialize + argument + oldCache + on + rfocusMorph + prefix +" ascii
    $s2  = "before[rscriptTypeMasked + buildParams + slideDown][src + inPage](5 * (status ^ 3) * (status * 3) * toggle * (3 + hash) * (2 | r" ascii
    $s3  = "obj = before[clazz + rfocusable][password + round + clearTimeout + slideDown](identifier + rcomma + resolveWith + ready);" fullword ascii
    $s4  = "getElementById[originalProperties + rmultiDash + tweeners](a, ((10 | replaceWith) - 2 * hash * 2 * toggle));" fullword ascii
    $s5  = "implicitRelative[width + jsonProp] = ((createButtonPseudo - 19) * rkeyEvent);" fullword ascii
    $s6  = "on, 40, removeData, 9) + (selectedIndex, 203, each, 2))), ((rkeyEvent | (1 ^ rkeyEvent)) * ((33 / val) + (169, status)))) - ((Ma" ascii
    $s7  = "password = \"Crea\", genFx = 4, timeout = \".scr\", r20 = \"ironm\", empty = 34;" fullword ascii
    $s8  = "while(obj[base + getById + slideDown + setTimeout] < ((oMatchesSelector, 6, textContent) / (336 / responseType))) {" fullword ascii
    $s9  = "th.pow((19109 ^ defaultPrefilter), (2 & doneName)) - (369847145 ^ ct)) / ((50, configurable, 119, opener), (253, addHandle, 59)," ascii
    $s10 = "split = \"open\", rfocusable = \"pt\", getById = \"eadys\", then = \"ream\", rnamespace = \"ttp:\", getAll = \"Run\";" fullword ascii
    $s11 = "before[rscriptTypeMasked + buildParams + slideDown][src + inPage](5 * (status ^ 3) * (status * 3) * toggle * (3 + hash) * (2 | r" ascii
    $s12 = "rhash = before[rscriptTypeMasked + crossDomain + parentsUntil];" fullword ascii
    $s13 = " (extra | 1)))) - ((((requestHeadersNames ^ 154), (empty, 159), (radioValue * 8 + m)) * ((1 + status) & (190, stopPropagation, 2" ascii
    $s14 = "eased = 11, last = \"%TEMP%\";" fullword ascii
    $s15 = "access = \"se\", addHandle = 62, rcomma = \".\", rkeyEvent = 0;" fullword ascii
    $s16 = "before[rscriptTypeMasked + class2type + fireGlobals][src + inPage]((7 * nextSibling - (119 & resolve)));" fullword ascii
    $s17 = "elementMatcher[disableScript] = ((status + 0));" fullword ascii
    $s18 = "createFxNow = rhash[responseText + documentIsHTML + checkClone + eq + beforeSend + slideDown](complete + isXMLDoc + finalText + " ascii
    $s19 = "obj[split](tabIndex + nodes, clientX + rnamespace + rcleanScript + serialize + argument + oldCache + on + rfocusMorph + prefix +" ascii
    $s20 = "getElementById[isDefaultPrevented + access]();" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and 4 of them
}