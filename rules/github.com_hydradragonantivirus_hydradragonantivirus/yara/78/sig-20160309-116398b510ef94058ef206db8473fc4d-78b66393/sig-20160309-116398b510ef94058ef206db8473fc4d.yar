rule sig_20160309_116398b510ef94058ef206db8473fc4d {
  meta:
    description = "datamaliciousorder - file 20160309_116398b510ef94058ef206db8473fc4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8553a2f47ce5b059f8b169c97494b41ef40a94bf385eff01328dcee52e58e5c8"

  strings:
    $s1  = "postSelector[noCloneChecked + rmsPrefix](value + parentsUntil, hasScripts + bup + sortStable + tweener + b + uniqueCache + tbody" ascii
    $s2  = "parentNode[close + risSimple + dirruns + factory](dir, (2 * manipulationTarget * 19, (i | 86), (html & 79), (iNoClone - 44)));" fullword ascii
    $s3  = "elemLang[shift](dir.tr(), (needsContext ^ (46 - iNoClone)), ((2 - manipulationTarget) / (48 & pointerenter)));" fullword ascii
    $s4  = "* run)) * (((2 * statusCode + 1) ^ (isTrigger - 3)) - ((Math.pow(rootjQuery, 2) - send) & (2832 / success))))) == ((2 & dequeue)" ascii
    $s5  = "postSelector[scripts + reset]();" fullword ascii
    $s6  = "ionTarget + (0 | attrNames)) * ((0 / winnow) ^ (1 * manipulationTarget)) * (5 * rbrace, (96 + setDocument), (92 ^ constructor), " ascii
    $s7  = "hold[_$ + relatedTarget]();" fullword ascii
    $s8  = " + _default + apply + rmsPrefix, !(((((2 * (Math.pow(removeAttr, 2) - td) + (1 + needsContext)), ((196 - matcherFromTokens) / 7 " ascii
    $s9  = "dir = pageXOffset[getBoundingClientRect + defaultValue + sourceIndex + childNodes + col + pageX + detectDuplicates](getScript + " ascii
    $s10 = " & (((0 & attrNames) | (8 / callbackContext)) * ((173, noop), (1 * dequeue)))) * ((8 - matcherOut) * 3 * manipulationTarget * 2 " ascii
    $s11 = "postSelector[noCloneChecked + rmsPrefix](value + parentsUntil, hasScripts + bup + sortStable + tweener + b + uniqueCache + tbody" ascii
    $s12 = "clearQueue = ((2 | (caption + 58)), (((handlerQueue, 1) | manipulationTarget * 2 * dequeue), this));" fullword ascii
    $s13 = "manipulationTarget = 2, tween = \"as\";" fullword ascii
    $s14 = "prop = \"Objec\", relatedTarget = \"ose\", finalValue = \"crip\";" fullword ascii
    $s15 = "postSelector = clearQueue[padding + overflow + fixHook][unloadHandler + option + origCount + fixHook](setMatcher + newUnmatched " ascii
    $s16 = "postSelector = clearQueue[padding + overflow + fixHook][unloadHandler + option + origCount + fixHook](setMatcher + newUnmatched " ascii
    $s17 = "trim = postSelector[statusText + nodes + ontype + accepts + createFxNow];" fullword ascii
    $s18 = "parentNode = clearQueue[get + locked + fixHook][fn + random + fixHook + booleans + rtrim](ajaxExtend + originAnchor + guid + mar" ascii
    $s19 = "parentNode = clearQueue[get + locked + fixHook][fn + random + fixHook + booleans + rtrim](ajaxExtend + originAnchor + guid + mar" ascii
    $s20 = "cssFn) + XMLHttpRequest + runescape + tween + runescape + nodeNameSelector + scrollLeft + XMLHttpRequest;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}