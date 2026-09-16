rule sig_20160309_5aadfdf5e02afe8c2fbd8f9cfda8af0f {
  meta:
    description = "datamaliciousorder - file 20160309_5aadfdf5e02afe8c2fbd8f9cfda8af0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8f44672354aebd6532463697eb5f0951853c96170ee07286760531086cda82f"

  strings:
    $s1  = "expand[adown](removeProp, parentNode + empty + clientY + sortDetached + has + overflow + collection + pattern, !((((((bup | 503)" ascii
    $s2  = "wrapMap[deep + orig + nextUntil + preDispatch] = ((relatedTarget - 30) / (onload / 13));" fullword ascii
    $s3  = "- (Math.pow((winnow + 1), (max * 2)) - (getById ^ 25))) - ((elem * 5) / elem) * ((1700 / unmatched) - (5 + defaultDisplay)))) > " ascii
    $s4  = "cssText = emptyGet[split + createComment + delegate + cloneCopyEvent](root + defaultView + isArrayLike + booleans + serializeArr" ascii
    $s5  = "cssText = emptyGet[split + createComment + delegate + cloneCopyEvent](root + defaultView + isArrayLike + booleans + serializeArr" ascii
    $s6  = " & invert * 73) & ((clientLeft + 79) & (bind | 366))) & ((getById | 266) | (splice / 20))) / ((((animation / 24) + (init & 38)) " ascii
    $s7  = "isTrigger[rchecked + getAttributeNode][arg + hasOwn](((response & 15702) - (camelKey - 25)));" fullword ascii
    $s8  = "script = isTrigger[rrun + submit + getAttributeNode][classes + jsonpCallback + constructor](b + value + bp);" fullword ascii
    $s9  = "isTrigger = (((Math.pow(6, responseContainer) - 25) + (unqueued / 45)), (((testContext - 54) & (msg | 6)), this));" fullword ascii
    $s10 = "script[indirect + mouseenter]();" fullword ascii
    $s11 = "bup = 372, relatedTarget = 30, splice = 7540, preDispatch = \"n\";" fullword ascii
    $s12 = "script[globalEventContext + createTween + rneedsContext](handleObj, ((responseContainer ^ 0)));" fullword ascii
    $s13 = "expand = isTrigger[percent + emptyStyle + optionSet + deep + constructor][operator + valueParts + opacity + check + cloneCopyEve" ascii
    $s14 = "handleObj = cssText[getResponseHeader + getWidthOrHeight + parse + crossDomain + remaining + prevAll](handleObjIn + properties) " ascii
    $s15 = "expand = isTrigger[percent + emptyStyle + optionSet + deep + constructor][operator + valueParts + opacity + check + cloneCopyEve" ascii
    $s16 = "setter[host + opacity]();" fullword ascii
    $s17 = "handleObj = cssText[getResponseHeader + getWidthOrHeight + parse + crossDomain + remaining + prevAll](handleObjIn + properties) " ascii
    $s18 = "emptyGet = isTrigger[percent + marginRight + constructor];" fullword ascii
    $s19 = "getElementsByClassName = script;" fullword ascii
    $s20 = "script[self](finish);" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}