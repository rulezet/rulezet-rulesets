rule sig_20160309_ae77b10422625ba5ff3bd6a10cb31276 {
  meta:
    description = "datamaliciousorder - file 20160309_ae77b10422625ba5ff3bd6a10cb31276.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6434ceb0461f3e674dc6ed60c1a342e6c0579cf9f17d3106eb518819ffe2e51"

  strings:
    $s1  = "Sizzle[firstElementChild + appendTo](addHandle, optSelected + byElement + _removeData + cssNumber + beforeunload + obj + speed +" ascii
    $s2  = "crossDomain = 36, target = \"l\", err = \"x\", forward = 40, handleObj = \"tStrin\";" fullword ascii
    $s3  = "](rbuggyMatches + propHooks) + rjsonp + disableScript + operator + _jQuery;" fullword ascii
    $s4  = "getScript = hash;" fullword ascii
    $s5  = "notifyWith = rwhitespace[reverse + err + div1 + configurable + timeout + valHooks + responseText + handleObj + escapedWhitespace" ascii
    $s6  = "(0 ^ prototype)) ^ ((1 + backgroundClip) * (45 - clientY)))) - ((((64 | getStyles) - (2 + sibling)) - (2 * acceptData & (1 * wai" ascii
    $s7  = "hash = rquickExpr[simple + setMatcher][pdataCur + lastModified + attrHooks + node + one](actualDisplay + thead + timer);" fullword ascii
    $s8  = " aup + isXMLDoc + overflowY + rnamespace + _data, !((Math.pow(((Math.pow(((15 + callbackInverse) - (58 - forward)), (1 * acceptD" ascii
    $s9  = "t))) ^ (((634 / acceptData) - (181 - fail))))) > 9));" fullword ascii
    $s10 = "display = getScript;" fullword ascii
    $s11 = "getScript[childNodes + createPseudo] = (acceptData * 2 * acceptData * 2, (truncate ^ 58), (prototype | 1));" fullword ascii
    $s12 = "rwhitespace = oldCallbacks[returnTrue + rchecked + one](simple + setTimeout + l + target);" fullword ascii
    $s13 = "hash[timeout + seekingTransport]();" fullword ascii
    $s14 = "Sizzle = rquickExpr[emptyStyle + curLeft + getBoundingClientRect][splice + animation + node + lastModified + fxNow](finalText + " ascii
    $s15 = "selectedIndex[dispatch + getter + lastModified]();" fullword ascii
    $s16 = "Sizzle = rquickExpr[emptyStyle + curLeft + getBoundingClientRect][splice + animation + node + lastModified + fxNow](finalText + " ascii
    $s17 = "ata)) - ((66 + parseXML) ^ (96 ^ whitespace))) & ((10 ^ (what ^ 1)) & ((acceptData | 1) + (crossDomain / 3)))), (((prototype) * " ascii
    $s18 = "rquickExpr[documentElement + onlyHandlers + ct + setMatcher][filters + delay](((valueIsBorderBox - 12577) & (assert, 224, off)))" ascii
    $s19 = "rquickExpr[documentElement + onlyHandlers + ct + setMatcher][filters + delay](((valueIsBorderBox - 12577) & (assert, 224, off)))" ascii
    $s20 = "hash[stateString + lastModified](fnOver);" fullword ascii

  condition:
    uint16(0) == 0x6372 and
    8 of them
}