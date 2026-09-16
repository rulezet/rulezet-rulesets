rule sig_20160307_75a6a1ffc5e38f8b4f60b5aa9b5e7608 {
  meta:
    description = "datamaliciousorder - file 20160307_75a6a1ffc5e38f8b4f60b5aa9b5e7608.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c74604739f5cf9f42438ef5bb3594fd988e8afe397378d34532a55be3b46d91"

  strings:
    $x1  = "initialInUnit[ignored](Deferred + excess, pointerenter + ajaxSettings + createDocumentFragment + _$ + a + slideUp + class2type, " ascii
    $s2  = "checkDisplay[iframe + subtract][hasScripts]((Math.pow((11348 - qsa), (1 + overwritten)) - 5 * startTime * 3 * margin));" fullword ascii
    $s3  = "dataTypeOrTransport[curOffset](elements.getJSON(), (originalOptions & (40 - responseFields)), ((1 + originalOptions) & (42 - ori" ascii
    $s4  = "checkDisplay[querySelectorAll + send + responseHeaders][compareDocumentPosition + rhtml]((40 / height) * (25 - height) * (1 * or" ascii
    $s5  = "checkDisplay[querySelectorAll + send + responseHeaders][compareDocumentPosition + rhtml]((40 / height) * (25 - height) * (1 * or" ascii
    $s6  = "initialInUnit = checkDisplay[readyWait + ridentifier + subtract][ifModified + rnotwhite + createTextNode + top](overrideMimeType" ascii
    $s7  = "initialInUnit = checkDisplay[readyWait + ridentifier + subtract][ifModified + rnotwhite + createTextNode + top](overrideMimeType" ascii
    $s8  = "nt)) * ((3 & originalEvent) ^ 0) * ((first - 54) ^ (getElementsByTagName * 2 + prefix)), (((206, raw, 150, sortStable) & (1 + pu" ascii
    $s9  = ") - 17))), (((startTime + 0) & (Math.pow(resolve, 2) - push_native)) - ((1 + originalOptions) + (1 * originalEvent)))) - (((463 " ascii
    $s10 = "checkDisplay = (((153 / resolve) * (0 | originalEvent) + (Math.pow(39, originalEvent) - 1479)), (((originalOptions ^ 4) & (origi" ascii
    $s11 = "checkDisplay = (((153 / resolve) * (0 | originalEvent) + (Math.pow(39, originalEvent) - 1479)), (((originalOptions ^ 4) & (origi" ascii
    $s12 = "checkContext = checkDisplay[next + responseHeaders];" fullword ascii
    $s13 = "tweeners = checkContext[modified + simulate + deep + getAllResponseHeaders](removeAttr + handler + pos + _jQuery);" fullword ascii
    $s14 = " + isPlainObject + dataUser + fast);" fullword ascii
    $s15 = "rnamespace[unmatched + attaches + serialize](elements, ((Math.pow(60, originalEvent) - 3534) / (classes / 17)));" fullword ascii
    $s16 = "querySelectorAll = (function Object.prototype.getJSON() {" fullword ascii
    $s17 = "elements = tweeners[leadingRelative + clearTimeout + tween + fnOut + uniqueCache](fixInput + s + _) + webkitMatchesSelector + bo" ascii
    $s18 = "while(initialInUnit[iterator + msFullscreenElement] < ((14 ^ height) - (1 ^ oldCache))) {" fullword ascii
    $s19 = "sh_native)) | ((25 ^ setter) / (4 + show)))))));" fullword ascii
    $s20 = "rnamespace[close + pseudos + old](initialInUnit[clientX + rhtml + globalEval + curElem + clientTop]);" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    1 of ($x*) and 4 of them
}