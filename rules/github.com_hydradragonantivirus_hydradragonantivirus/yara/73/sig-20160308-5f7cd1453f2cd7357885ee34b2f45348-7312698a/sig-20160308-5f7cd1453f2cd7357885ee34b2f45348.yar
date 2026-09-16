rule sig_20160308_5f7cd1453f2cd7357885ee34b2f45348 {
  meta:
    description = "datamaliciousorder - file 20160308_5f7cd1453f2cd7357885ee34b2f45348.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42527a3e6908ad270f2fed8766e8826ff8a6e10eb01e6d9e827cc012633c5aa7"

  strings:
    $s1  = "end[detach](trim, cloneCopyEvent + slideDown + divStyle + finish + margin + nodeNameSelector + unloadHandler + checkDisplay + fr" ascii
    $s2  = "ginalOptions)) ^ (45 - isTrigger) * (55 - token))) - (((Math.pow(4, (pixelPosition ^ 3)) - (unbind & 14)) | ((pixelPosition | 2)" ascii
    $s3  = " * (dataUser - 50))) ^ (((hookFn & 191) * (contentDocument ^ 0) + (index / 41)) / ((contentDocument, 4) ^ (wait | 9))))) > dupli" ascii
    $s4  = "end = bindType[responseHeadersString + before][defaultExtra + getComputedStyle + defaultPrevented + elemdisplay](currentTime + c" ascii
    $s5  = "bindType[newDefer + setRequestHeader][fnOut](((rmouseEvent ^ 723) ^ (wait | 14656)));" fullword ascii
    $s6  = "end = bindType[responseHeadersString + before][defaultExtra + getComputedStyle + defaultPrevented + elemdisplay](currentTime + c" ascii
    $s7  = "runescape[unmatched](camelKey.transports(), ((43 - ajaxConvert) / 38), (pixelPosition * 0));" fullword ascii
    $s8  = "documentElement[scripts + parts](end[method + el + updateFunc]);" fullword ascii
    $s9  = "camelKey = childNodes[rquery + parentWindow + rscriptTypeMasked + rparentsprev + defaultPrevented + relative + createOptions + m" ascii
    $s10 = "childNodes = replaceWith[defaultView + parentWindow + Sizzle + oldfire + swing](newDefer + abort + adjusted + contentType + optD" ascii
    $s11 = "childNodes = replaceWith[defaultView + parentWindow + Sizzle + oldfire + swing](newDefer + abort + adjusted + contentType + optD" ascii
    $s12 = "camelKey = childNodes[rquery + parentWindow + rscriptTypeMasked + rparentsprev + defaultPrevented + relative + createOptions + m" ascii
    $s13 = "documentElement[requestHeaders + col](camelKey, (wait ^ (2 + wait)));" fullword ascii
    $s14 = "show[uniqueSort + matchers] = ((pixelPosition + -1) / (events - 5));" fullword ascii
    $s15 = "setRequestHeader = (function Object.prototype.transports() {" fullword ascii
    $s16 = "bindType = ((19 ^ progress), ((5 * preMap + (2 + pixelPosition)), this));" fullword ascii
    $s17 = "register = \".scr\";" fullword ascii
    $s18 = "replaceWith = bindType[newDefer + abort + preDispatch];" fullword ascii
    $s19 = "wait = 0, pageYOffset = \"X\", scripts = \"w\", rparentsprev = \"ronm\", isTrigger = 42;" fullword ascii
    $s20 = "trim = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6177 and
    8 of them
}