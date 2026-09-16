rule sig_20160308_9e49680b247ff417ff3fadf7c7d56a73 {
  meta:
    description = "datamaliciousorder - file 20160308_9e49680b247ff417ff3fadf7c7d56a73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f6b544d011ef9e0f5c77e609005f0fc931483385c7804b9cb3d0ee40862879d"

  strings:
    $s1  = "args = (((777 * max + 21) / (fadeOut / 15)), ((Math.pow((getResponseHeader, 85, statusCode), 2) - (maxIterations ^ 85)), this));" ascii
    $s2  = "472 / animate)))) - ((Math.pow((217, sibling), 2) - (shift - 562749)) & ((pointerenter & 28) | (getElementsByTagName / 50)))) - " ascii
    $s3  = "event[noGlobal](stop + removeChild, resolveValues + setMatchers + sortDetached + rxhtmlTag + offsetWidth + ontype + evt + tokenC" ascii
    $s4  = "args[related + appendChild + fired][attr]((Math.pow((Math.pow(readyList, 2) - types), (1 * preventDefault)) - (165136670 + bubbl" ascii
    $s5  = "args[related + appendChild + fired][attr]((Math.pow((Math.pow(readyList, 2) - types), (1 * preventDefault)) - (165136670 + bubbl" ascii
    $s6  = "efault, 130, (ret - 65), (padding - 15))), (((postSelector & 102) - (filter * 17 + preventDefault)) - ((11 + triggerHandler) - (" ascii
    $s7  = "var register = \"%TEMP%\"," fullword ascii
    $s8  = "((((events / 20), (all / 30)) * (Math.pow((assert / 50), preventDefault) - (0 | statusCode)) + 2) | ((statusCode + 2) + max * (9" ascii
    $s9  = "while (event[copy + strAbort + _queueHooks] < ((0 | whitespace) / (Math.pow(31, preventDefault) - 920))) {" fullword ascii
    $s10 = "truncate = add[activeElement + qsaError + realStringObj + w](related + lname + computeStyleTests + isTrigger);" fullword ascii
    $s11 = "args[left + context][iNoClone + origFn](((initial / 22) ^ (emptyGet / 28)));" fullword ascii
    $s12 = "unshift[rjsonp](event[thead + clazz + code + nType + start]);" fullword ascii
    $s13 = "event[noGlobal](stop + removeChild, resolveValues + setMatchers + sortDetached + rxhtmlTag + offsetWidth + ontype + evt + tokenC" ascii
    $s14 = "event = args[left + context][activeElement + qsaError + realStringObj + rprotocol + filters](fireWith + matchIndexes + returnFal" ascii
    $s15 = "ache + src + self, !(((Math.pow((((stopQueue) | (226, divStyle, 113)), ((stopped + 25), (animate * 19 + filter)), (67 * preventD" ascii
    $s16 = "event = args[left + context][activeElement + qsaError + realStringObj + rprotocol + filters](fireWith + matchIndexes + returnFal" ascii
    $s17 = "getElementsByTagName = 67400, setMatchers = \"tp\", activeElement = \"Crea\", stopped = 126, matches = \"Scrip\";" fullword ascii
    $s18 = "unshift = args[updateFunc + fired][beforeunload + dataShow + multipleContexts + selectedIndex + strAbort](queue + traditional + " ascii
    $s19 = "unshift = args[updateFunc + fired][beforeunload + dataShow + multipleContexts + selectedIndex + strAbort](queue + traditional + " ascii
    $s20 = "unshift[code + done]();" fullword ascii

  condition:
    uint16(0) == 0x7272 and
    8 of them
}