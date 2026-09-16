rule sig_20160307_86367fc63e48f5ebd0e262a973e4bcbb {
  meta:
    description = "datamaliciousorder - file 20160307_86367fc63e48f5ebd0e262a973e4bcbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "966451c0952a7d9925621e6506e62533a448b29652dc85d285b284feeb327e91"

  strings:
    $s1  = "getById = removeAttribute[nextAll + a + complete + animate + specialEasing + content + speeds](keys + isWindow) + noop + rmsPref" ascii
    $s2  = "getById = removeAttribute[nextAll + a + complete + animate + specialEasing + content + speeds](keys + isWindow) + noop + rmsPref" ascii
    $s3  = "stopImmediatePropagation[suffix](hidden, attrHandle + addEventListener + send + filters + click + tokens + pnum + setMatcher + r" ascii
    $s4  = "while(stopImmediatePropagation[setRequestHeader + progressValues + checkNonElements] < ((augmentWidthOrHeight * 2 + rparentsprev" ascii
    $s5  = " (((0 | reverse) ^ (45 - getWidthOrHeight)), this));" fullword ascii
    $s6  = "removeAttr = (((Math.pow(206, opener) - 42199), (Math.pow(returnFalse, 2) - callbackContext), (18 + modified), (107 & oldfire))," ascii
    $s7  = "elated, !((((((Math.pow(171, opener) - 29052) - (m)) / ((9 ^ simple) * (1 ^ nodeIndex) + (1 * visibility))) + ((1 | clearInterva" ascii
    $s8  = "removeAttr[percent + factory][ap + collection](((overwritten - 1503) / (Math.pow(parentOffset, 2) - noGlobal)));" fullword ascii
    $s9  = "stopImmediatePropagation = removeAttr[percent + factory][pdataOld + step + originalSettings + fixHook + disableScript](wrap + ab" ascii
    $s10 = "open = removeAttr[first + xhrFields + tfoot + disableScript];" fullword ascii
    $s11 = "stopImmediatePropagation[suffix](hidden, attrHandle + addEventListener + send + filters + click + tokens + pnum + setMatcher + r" ascii
    $s12 = "stopImmediatePropagation = removeAttr[percent + factory][pdataOld + step + originalSettings + fixHook + disableScript](wrap + ab" ascii
    $s13 = "removeAttr[code + originalOptions][time](((142 & scripts), (1447 + nodes)));" fullword ascii
    $s14 = "while(stopImmediatePropagation[setRequestHeader + progressValues + checkNonElements] < ((augmentWidthOrHeight * 2 + rparentsprev" ascii
    $s15 = "options[simulate](getById.matchers(), (nodeIndex * 3 * init, 0), ((reverse / 6) & (clearInterval * 1)));" fullword ascii
    $s16 = "opener = 2, factory = \"pt\", speeds = \"s\", hidden = \"GET\";" fullword ascii
    $s17 = "test[noCloneChecked + handleObjIn + charCode](getById, (1 * (opener & 3)));" fullword ascii
    $s18 = "), ((0 | (index & 31)) / (opener + (62 - doScroll)))) - (((3354 & ajaxHandleResponses) / 3 * rmouseEvent) & ((7 | opt) * (1 * ge" ascii
    $s19 = "), (17 + visibility), (33 * nodeIndex + 16), (jqXHR - 20))) {" fullword ascii
    $s20 = "nit + (64 ^ visibility)) / ((6 + reverse) + (3 & nodeIndex))) & ((1 + -clearInterval) | 5) * ((clearInterval * 45) - (elems - 78" ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}