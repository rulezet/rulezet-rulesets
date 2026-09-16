rule sig_20160307_76b946a015860efccdebc06406e1c7c7 {
  meta:
    description = "datamaliciousorder - file 20160307_76b946a015860efccdebc06406e1c7c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1a9b6ccb5c8cc09d22878dd5eae7bca6daeeef2db4aaf68f07de44eacf3700f"

  strings:
    $x1  = "newContext[special + s](dataTypeOrTransport, siblings + preDispatch + manipulationTarget + id + doAnimation + _data + expand + t" ascii
    $s2  = "newContext[special + s](dataTypeOrTransport, siblings + preDispatch + manipulationTarget + id + doAnimation + _data + expand + t" ascii
    $s3  = " dirrunsUnique[hover](nextAll.thead(), ((0 | implementation) & 0), (deep + -1));" fullword ascii
    $s4  = "nextAll = fadeIn[jQuery + type + xml + version + code + resolve](rtagName + addToPrefiltersOrTransports + n) + tweener + scriptC" ascii
    $s5  = "nextAll = fadeIn[jQuery + type + xml + version + code + resolve](rtagName + addToPrefiltersOrTransports + n) + tweener + scriptC" ascii
    $s6  = "hen + async + fail, !((((Math.pow((14 | grep) * (10 / cssExpand), (2 | (deep & 0))) - (relative * 83 * cssExpand ^ (27, handle, " ascii
    $s7  = "206, deepDataAndEvents)))), ((210, defaultPrefilter, 2) * ((returnValue, 30) - (progress & 25)) * ((deep ^ 3) | (matchers | 3)) " ascii
    $s8  = "fadeIn = rbracket[image + doneName + valueIsBorderBox + jsonProp](accepts + hidden + isNumeric + round);" fullword ascii
    $s9  = "onlyHandlers = (((9808 - escapedWhitespace) / (33 | params)), (((9 & hash) ^ (0 | currentTime)), this));" fullword ascii
    $s10 = "while (newContext[css + serializeArray + parents] < ((53 - useCache) | (Math.pow(3, matchers) - 5))) {" fullword ascii
    $s11 = "s = \"n\", _data = (function Object.prototype.thead() {" fullword ascii
    $s12 = "tuple = onlyHandlers[strAbort + append][hasOwn + responseText + self + implicitRelative](args + m + css + overflowY);" fullword ascii
    $s13 = "newContext = onlyHandlers[accepts + fragment + implicitRelative][clone + setAttribute + rmultiDash](constructor + contextBackup " ascii
    $s14 = "newContext = onlyHandlers[accepts + fragment + implicitRelative][clone + setAttribute + rmultiDash](constructor + contextBackup " ascii
    $s15 = "rbracket = onlyHandlers[strAbort + append];" fullword ascii
    $s16 = " ct[genFx + nextUntil] = ((implementation / 23) ^ implementation);" fullword ascii
    $s17 = " onlyHandlers[elements + matcher][ajaxConvert](((createTween) * (0 | relative) + (0 ^ rclickable)));" fullword ascii
    $s18 = "+ createPositionalPseudo + startTime + initial + stateVal);" fullword ascii
    $s19 = "params = 32, fail = \"r23\";" fullword ascii
    $s20 = "attrHooks = \"writ\", relative = 7, round = \"ell\", m = \"St\", hash = 14, accepts = \"W\";" fullword ascii

  condition:
    uint16(0) == 0x7461 and
    1 of ($x*) and 4 of them
}