rule sig_20160308_0eae73249810e072445fd1896e4c669c {
  meta:
    description = "datamaliciousorder - file 20160308_0eae73249810e072445fd1896e4c669c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4458a64323543bcba41c902973bc6e53b23f3cbf184edcadd0e480042af61ea7"

  strings:
    $s1  = "replaceAll[contextBackup](filter + values, globalEventContext + matchedCount + ontype + proxy + useCache + clazz + firingIndex +" ascii
    $s2  = "stopQueue[disable](container.transports(), ((39 - collection) + -(1 * addGetHookIf)), (0 & (r20 ^ 1)));" fullword ascii
    $s3  = "idx[promise + computeStyleTests + iterator](container, ((13 - _$) + (1 * r20)));" fullword ascii
    $s4  = "escaped[addToPrefiltersOrTransports + pointerenter][implementation + camel]((uniqueID - (Math.pow(7339, removeClass) - 53846348)" ascii
    $s5  = "escaped[addToPrefiltersOrTransports + pointerenter][implementation + camel]((uniqueID - (Math.pow(7339, removeClass) - 53846348)" ascii
    $s6  = "contentType[progress + valueParts] = (1 * r20);" fullword ascii
    $s7  = " option + originalEvent + rdisplayswap + parsed, !(10 == ((((multipleContexts | 84) / (method, 11, groups, 42)) * ((cssExpand - " ascii
    $s8  = "while (replaceAll[s + parentsUntil + clearInterval] < ((1 - r20) + (132 / rlocalProtocol))) {" fullword ascii
    $s9  = "escaped = (((5 * toSelector + 4), (groups ^ 56), (_$ * 10), (rlocalProtocol * 4 + fadeTo)), (((487 - modified), (25 / guaranteed" ascii
    $s10 = "classNames = getClientRects[unquoted + l + charset + rcheckableType](throws + responseFields + th);" fullword ascii
    $s11 = "replaceAll = escaped[each + option + pointerenter][unquoted + body + click + pageY](contents + cloneNode + evt + docElem);" fullword ascii
    $s12 = "28) / (content + 4)) * (removeClass + 5) * ((defaultExtra, 253, a) & (5 ^ r20)) * (2 | always) * ((1 + r20) | (1 * a)) / (4 * (r" ascii
    $s13 = "contents = \"MS\";" fullword ascii
    $s14 = "content = 18;" fullword ascii
    $s15 = "idx[cssFn](replaceAll[until + namespace]);" fullword ascii
    $s16 = "replaceAll[parentWindow + triggered]();" fullword ascii
    $s17 = "idx[ajaxPrefilter + before + firstDataType]();" fullword ascii
    $s18 = "proxy = \"vtipn\";" fullword ascii
    $s19 = "excess = \".Str\";" fullword ascii
    $s20 = "replaceAll[contextBackup](filter + values, globalEventContext + matchedCount + ontype + proxy + useCache + clazz + firingIndex +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}