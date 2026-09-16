rule sig_20160308_537e626072a3ffbde44169bfd4fd6c50 {
  meta:
    description = "datamaliciousorder - file 20160308_537e626072a3ffbde44169bfd4fd6c50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a388396493f7ad7491486577733d58487baa2a3bfa337e54c743f098a4f0bbc"

  strings:
    $s1  = "val[raw + register + Expr](newDefer, doAnimation + trigger + callbackExpect + disable + fixInput + m + replaceWith + wrapAll + r" ascii
    $s2  = "isPropagationStopped = defaultDisplay[mappedTypes + elements + setup + parts + headers + one](fadeTo + finalText) + sort + preFi" ascii
    $s3  = "rnoContent[delegate] = ((153 & delay), (4532 / stateString), (32 + isArrayLike), 1);" fullword ascii
    $s4  = "tweeners[udataCur + raw + match](isPropagationStopped, ((Math.pow(37, once) - 1325) / (marginRight ^ 7)));" fullword ascii
    $s5  = "attachEvent[finalDataType + nodeIndex][slideDown + locked + win]((Math.pow(14458, (once | 2)) - fix));" fullword ascii
    $s6  = "tweeners = attachEvent[script + eventPath][select + augmentWidthOrHeight + code](invert + ifModified + dir + tuples);" fullword ascii
    $s7  = "oot + setter + rmouseEvent + originalSettings + rtrim + computeStyleTests, !((Math.pow((((image & 12) ^ uid) | (0 | uid)), ((1 &" ascii
    $s8  = "defaultDisplay = test[keyHooks + cssText + token + filter + async](hold + elemData + pixelMarginRightVal + newContext);" fullword ascii
    $s9  = "isPropagationStopped = defaultDisplay[mappedTypes + elements + setup + parts + headers + one](fadeTo + finalText) + sort + preFi" ascii
    $s10 = "test = attachEvent[username + results + async];" fullword ascii
    $s11 = "lters + cssShow + serialize + dequeue + seekingTransport + defaultValue;" fullword ascii
    $s12 = "    attachEvent[script + eventPath][rcheckableType + marginDiv](((195, originalEvent, 23, uid) | (100 | ready)));" fullword ascii
    $s13 = "headers = \"tStri\", serialize = \"i\";" fullword ascii
    $s14 = "attachEvent = ((13 * once * 2 * (isArrayLike ^ 7) + (rneedsContext & 7)), (((triggerHandler, 157, pointerenter, 440) / once * 11" ascii
    $s15 = "tweeners[webkitMatchesSelector + serialize + matchIndexes](val[hasData + check + rdisplayswap + percent + cors]);" fullword ascii
    $s16 = "while(val[lastModified + prototype] < ((2 | once) + (1 + gotoEnd))) {" fullword ascii
    $s17 = "attachEvent = ((13 * once * 2 * (isArrayLike ^ 7) + (rneedsContext & 7)), (((triggerHandler, 157, pointerenter, 440) / once * 11" ascii
    $s18 = "tweeners[filter + accepts + base]();" fullword ascii
    $s19 = "delay = 199, doAnimation = \"h\", finalDataType = \"WScri\", hold = \"WS\", token = \"bje\";" fullword ascii
    $s20 = "    script = \"W\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}