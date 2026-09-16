rule sig_20160307_6f0ccb091abceb5c3766eeffa12119f4 {
  meta:
    description = "datamaliciousorder - file 20160307_6f0ccb091abceb5c3766eeffa12119f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ea83b3292f11939e7cd3afab094ca03c88c0d22506e794804bd3a4bb48e8618"

  strings:
    $s1  = "isWindow[events + which][nextSibling + funcName](((getScript - 55), (disableScript & 251), (Math.pow(animation, 2) - isSuccess)," ascii
    $s2  = "isWindow[events + which][nextSibling + funcName](((getScript - 55), (disableScript & 251), (Math.pow(animation, 2) - isSuccess)," ascii
    $s3  = "boxSizingReliable[mouseleave + excess](rejectWith + nativeStatusText, method + offsetParent + finalDataType + rreturn + setMatch" ascii
    $s4  = "lTo) * 3) + (Math.pow((bulk ^ 27), (postFilter, 2)) - (isTrigger ^ 447))), (((dir + 68) - (undelegate ^ 116)) & (xhrSuccessStatu" ascii
    $s5  = "cssFn[fast + elemData] = (1 * manipulationTarget);" fullword ascii
    $s6  = "origType = id[guaranteedUnique + access + pattern + href + parseFromString + rsibling + send + tabIndex](original + round) + sim" ascii
    $s7  = "original = \"%TEMP%\";" fullword ascii
    $s8  = "value = isWindow[getElementsByName + scripts + status][left + getPropertyValue + buildFragment + escaped](hasFocus + readyWait +" ascii
    $s9  = "value = isWindow[getElementsByName + scripts + status][left + getPropertyValue + buildFragment + escaped](hasFocus + readyWait +" ascii
    $s10 = "unit[not](origType.callbackInverse(), ((162 & step), (65, setter, 130, manipulationTarget)), (0 & (scrollTo * 0)));" fullword ascii
    $s11 = "boxSizingReliable = isWindow[hover + onerror + status][transports + overflowY + fragment](stopPropagation + body + border + sele" ascii
    $s12 = "id = padding[transports + reject + bind](events + nodeNameSelector + properties);" fullword ascii
    $s13 = "boxSizingReliable = isWindow[hover + onerror + status][transports + overflowY + fragment](stopPropagation + body + border + sele" ascii
    $s14 = "isWindow = ((2 * offsetWidth * 2 * (input - 32) + (offsetWidth + 27)), (((preFilters, 31, flatOptions) & 15), this));" fullword ascii
    $s15 = " (126 - once)));" fullword ascii
    $s16 = "visibility = \"Body\", contentDocument = \"nd\", uniqueSort = \"f3\", wrapAll = 22, elemData = \"ion\", tokens = \"se\";" fullword ascii
    $s17 = "while(boxSizingReliable[mouseHooks + jQuery + clearCloneStyle + matcher + response] < ((protocol - 6) - (wrapAll - 11))) {" fullword ascii
    $s18 = "value[sourceIndex + which + dataTypeExpression](boxSizingReliable[eventHandle + tokens + visibility]);" fullword ascii
    $s19 = "er + Data + writable + ifModified + uniqueSort, !(((Math.pow(((rtrim ^ 53), (nodes / 10)) * ((matches ^ 20) / (protocol * 2)) * " ascii
    $s20 = "value[setMatcher + fail]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}