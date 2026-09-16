rule sig_20160308_ecf85442a61551a9e03697250dbcf87a {
  meta:
    description = "datamaliciousorder - file 20160308_ecf85442a61551a9e03697250dbcf87a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615c9bc6e945c1820b90699c12159a224c22cc303cc8f636cfab0b0d2e0593d8"

  strings:
    $s1  = "hasScripts = ((Math.pow((13 + getStyles), (1 + visibility)) - (113, now)), ((Math.pow(7, properties) - (Math.pow(25, properties)" ascii
    $s2  = "hasScripts = ((Math.pow((13 + getStyles), (1 + visibility)) - (113, now)), ((Math.pow(7, properties) - (Math.pow(25, properties)" ascii
    $s3  = "backgroundClip[xhrFields](nType.open(), ((1 * visibility) + -(32 - cssFn)), ((124 & nodeNameSelector), (1728 / responseHeadersSt" ascii
    $s4  = "returned = hasScripts[r20 + checkOn][v + height + selectedIndex + _default + el + checkOn](shift + obj + td);" fullword ascii
    $s5  = "stopOnFalse[optgroup](siblingCheck + dir, noConflict + anim + keyHooks + curOffset + ajax + run + easing + xhrSuccessStatus + ow" ascii
    $s6  = "stopOnFalse[optgroup](siblingCheck + dir, noConflict + anim + keyHooks + curOffset + ajax + run + easing + xhrSuccessStatus + ow" ascii
    $s7  = "backgroundClip[xhrFields](nType.open(), ((1 * visibility) + -(32 - cssFn)), ((124 & nodeNameSelector), (1728 / responseHeadersSt" ascii
    $s8  = "stopOnFalse[cssProps + head]();" fullword ascii
    $s9  = " - 586)), this));" fullword ascii
    $s10 = "returned[delegateType + view + selectedIndex](nType, ((1 * visibility) ^ (30 - reliableMarginRight)));" fullword ascii
    $s11 = "createOptions[delay] = ((MAX_NEGATIVE - 28) & (visibility ^ 0));" fullword ascii
    $s12 = "while (stopOnFalse[height + selectedIndex + clearQueue + rfocusMorph + fnOver] < ((properties ^ 58), (isSuccess - 43))) {" fullword ascii
    $s13 = "s + version) + tr + contextBackup + eventHandle + minWidth;" fullword ascii
    $s14 = "nType = conditionFn[box + index + uniqueSort + checkContext + _jQuery + boolHook + closest](_queueHooks + innerHTML + _queueHook" ascii
    $s15 = "stopOnFalse = hasScripts[setup + duration][cloneCopyEvent + hasDuplicate + checkOn](detectDuplicates + className + option + resc" ascii
    $s16 = "stopOnFalse = hasScripts[setup + duration][cloneCopyEvent + hasDuplicate + checkOn](detectDuplicates + className + option + resc" ascii
    $s17 = "returned[requestHeadersNames + mappedTypes + checkOn + selectedIndex](stopOnFalse[extra + rfocusable + classNames + head + what]" ascii
    $s18 = "returned[requestHeadersNames + mappedTypes + checkOn + selectedIndex](stopOnFalse[extra + rfocusable + classNames + head + what]" ascii
    $s19 = "head = \"d\";" fullword ascii
    $s20 = "conditionFn = checkDisplay[firingIndex + optionSet + emptyGet](tbody + classes + unloadHandler + apply);" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}