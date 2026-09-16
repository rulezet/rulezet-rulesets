rule sig_20160308_3c9df7978ccb23e1683cccc164c6b016 {
  meta:
    description = "datamaliciousorder - file 20160308_3c9df7978ccb23e1683cccc164c6b016.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4de806fb2781210c60d7116a330425fac2b52b419d672da7a715509261e73773"

  strings:
    $s1  = "first[isLocal](useCache + end, nodeNameSelector + pdataCur + overwritten + progressValues + disable + oldCache + timer + suffix " ascii
    $s2  = "+ indirect, !((Math.pow(((((256 - fnOver), (373 - bup)), ((660 / onload) + (61 & resolveContexts)), (129 - script) * (2 & rhtml)" ascii
    $s3  = "fx[matchesSelector + delegateType + getComputedStyle][globalEventContext](((35306 - getter) - (1438 ^ curLeft)));" fullword ascii
    $s4  = "newDefer = rscriptType[requestHeadersNames + valueIsBorderBox + crossDomain + rbuggyQSA + fadeTo + hold + swap + xhrFields + amd" ascii
    $s5  = "time = fx[cors + getComputedStyle][rnoInnerhtml + rcombinators](postMap + when + holdReady + eventPath);" fullword ascii
    $s6  = "first = fx[before + setFilters][bySet + getComputedStyle + returnTrue + handlers](relatedTarget + hasClass + pos + interval + gl" ascii
    $s7  = "first = fx[before + setFilters][bySet + getComputedStyle + returnTrue + handlers](relatedTarget + hasClass + pos + interval + gl" ascii
    $s8  = " & (0 | conv))) * (((1 + rnoContent) + (13 - etag)) + ((15 + high), 0)))) - ((((Math.pow(pageX, 2) - escaped) / (11 + rhtml)) * " ascii
    $s9  = "newDefer = rscriptType[requestHeadersNames + valueIsBorderBox + crossDomain + rbuggyQSA + fadeTo + hold + swap + xhrFields + amd" ascii
    $s10 = ", (1 * step)) ^ (((635 & prevAll) / (Math.pow(18, step) - 305)), (Math.pow(matcher * 3 * rhtml, 2) - (bup, 116, checked, 9682))," ascii
    $s11 = "reliableMarginLeftVal[load](newDefer.bool(), ((augmentWidthOrHeight ^ 59) - (uniqueCache & 35)), ((fadeOut) - (32 & emptyGet)));" ascii
    $s12 = "time[rheader + global]();" fullword ascii
    $s13 = "time[structure + returnFalse + push](newDefer, ((stop | 149), (JSON - 44)));" fullword ascii
    $s14 = "while(first[implicitRelative + attrHooks] < ((pixelMarginRight) / (90 - _removeData))) {" fullword ascii
    $s15 = "method = \"%/\", matcherIn = \"Script\", originAnchor = 15, nType = \"wr\";" fullword ascii
    $s16 = "script = 28;" fullword ascii
    $s17 = "getter = 17141," fullword ascii
    $s18 = "rnoContent = 0, returnFalse = \"eToFil\", bySet = \"Crea\", append = 5, swap = \"in\", tween = \"apA\";" fullword ascii
    $s19 = " (append | (49 & cacheURL)), ((1092 / responseContainer) / (12 + rnoContent)))), ((((1 ^ rnoContent) * (1 * conv)) * ((0 ^ conv)" ascii
    $s20 = "64)) / ((win * 6 + genFx) & (55 & fragment))))) == 7));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}