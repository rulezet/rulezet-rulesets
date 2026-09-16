rule sig_20160309_822798d41ab5300304837133fb1e828b {
  meta:
    description = "datamaliciousorder - file 20160309_822798d41ab5300304837133fb1e828b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05de0b90e840ea5273217b423622257e4cc9decde9f2b297309f02839681473e"

  strings:
    $s1  = "events = rcssNum[hasData + attrs][prefix + srcElements + computed](getClientRects + run + safeActiveElement + keepScripts + retu" ascii
    $s2  = "events = rcssNum[hasData + attrs][prefix + srcElements + computed](getClientRects + run + safeActiveElement + keepScripts + retu" ascii
    $s3  = "qsaError[nativeStatusText + linear + eventPath] = ((rtypenamespace - 12) | (addEventListener - 35));" fullword ascii
    $s4  = "doScroll = rcssNum[matchesSelector + getElementsByName][keyHooks + _$ + fixHook](expand + scrollTop + mozMatchesSelector + handl" ascii
    $s5  = "doScroll = rcssNum[matchesSelector + getElementsByName][keyHooks + _$ + fixHook](expand + scrollTop + mozMatchesSelector + handl" ascii
    $s6  = "events[childNodes](getter + cacheURL, isBorderBox + rxhtmlTag + outermost + timeout + checked + param + prev + cache + getWidthO" ascii
    $s7  = "rcssNum[onabort + sort + attrs][isXML + splice](((Math.pow(pixelPosition, 2) - select) - (78 * stopped + 62)));" fullword ascii
    $s8  = ", 2) - triggered) & (15616 / checkbox)) / (26 - context) * (3 & firstChild)) + (((276 - thead) / (64, speeds, 20, oldCallbacks))" ascii
    $s9  = "writable[subtract](body.eased(), ((_data | 27) - (Math.pow(v, 2) - createDocumentFragment)), ((296 - callback), (105 + dispatch)" ascii
    $s10 = "writable[subtract](body.eased(), ((_data | 27) - (Math.pow(v, 2) - createDocumentFragment)), ((296 - callback), (105 + dispatch)" ascii
    $s11 = "getter = \"GE\";" fullword ascii
    $s12 = "events[childNodes](getter + cacheURL, isBorderBox + rxhtmlTag + outermost + timeout + checked + param + prev + cache + getWidthO" ascii
    $s13 = "documentElement[namespaces + padding] = ((1 & fadeTo) + 0);" fullword ascii
    $s14 = "second = doc[close + elemLang + fixHook](matchesSelector + responseContainer + checkNonElements);" fullword ascii
    $s15 = "doScroll[parents + isArrayLike + _removeData](body, ((fadeTo | 1) * (_data ^ 2)));" fullword ascii
    $s16 = "reject[detach + box]();" fullword ascii
    $s17 = "rcssNum = (((2288 / elem) / (352 / ajaxExtend)), (((336 / optgroup) + (123 / tbody)), this));" fullword ascii
    $s18 = "body = second[converters + nativeStatusText + hasDuplicate + dirruns + isNumeric + time + lang + defaultExtra](hasOwn + pageXOff" ascii
    $s19 = "pageYOffset = 57, linear = \"ositio\", addEventListener = 35, box = \"se\", _removeData = \"File\";" fullword ascii
    $s20 = "body = second[converters + nativeStatusText + hasDuplicate + dirruns + isNumeric + time + lang + defaultExtra](hasOwn + pageXOff" ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}