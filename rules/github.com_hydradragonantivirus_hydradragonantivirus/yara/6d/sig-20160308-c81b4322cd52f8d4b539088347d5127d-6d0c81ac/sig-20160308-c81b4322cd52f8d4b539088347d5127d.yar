rule sig_20160308_c81b4322cd52f8d4b539088347d5127d {
  meta:
    description = "datamaliciousorder - file 20160308_c81b4322cd52f8d4b539088347d5127d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bea991201118f9ee62af0bc2502c18ced8a2b178a4f71fa95daca10f65731ab7"

  strings:
    $s1  = "exports = rmouseEvent[border + targets + open + clearCloneStyle + matches][curLeft + structure + compareDocumentPosition + rdash" ascii
    $s2  = "exports[relatedTarget + rnamespace](tr, urlAnchor + matches + fontWeight + disabled + uniqueID + _load + parent + curCSS + timer" ascii
    $s3  = "exports = rmouseEvent[border + targets + open + clearCloneStyle + matches][curLeft + structure + compareDocumentPosition + rdash" ascii
    $s4  = "exports[relatedTarget + rnamespace](tr, urlAnchor + matches + fontWeight + disabled + uniqueID + _load + parent + curCSS + timer" ascii
    $s5  = "tween[bool](ajaxTransport.rheaders(), ((ret & 1) ^ (chainable - 9)), (elem + -(0 | elem)));" fullword ascii
    $s6  = "while (exports[th + originalEvent] < ((Math.pow(rxhtmlTag, 2) - isPlainObject) & (21 - origType))) {" fullword ascii
    $s7  = "ajaxTransport = parseXML[top + triggered + resolveValues + attrs + rnamespace + mapped + errorCallback](orig + throws) + tick + " ascii
    $s8  = "rmouseEvent[border + attributes + uniqueID + parseJSON][overwritten + firstElementChild]((Math.pow((Math.pow(59, fnOut) - 3396)," ascii
    $s9  = "rmouseEvent[border + attributes + uniqueID + parseJSON][overwritten + firstElementChild]((Math.pow((Math.pow(59, fnOut) - 3396)," ascii
    $s10 = "focus + fromCharCode + getWidthOrHeight + rlocalProtocol + tokenize;" fullword ascii
    $s11 = "container = 59, contentDocument = \"i\", tr = \"GET\";" fullword ascii
    $s12 = "Alpha + parentNode](selector + assert + token + tmp + elemdisplay);" fullword ascii
    $s13 = "rmouseEvent[defineProperty + matches][script + clearCloneStyle](((expanded | 74976) / (isPlainObject & 7)));" fullword ascii
    $s14 = "detectDuplicates = rmouseEvent[node + tokenize + factory][pixelMarginRightVal + createFxNow + jsonp + nid + extra + restoreScrip" ascii
    $s15 = "parseXML = opener[pixelMarginRightVal + contextBackup + nid + hasOwn + matches](value + contentDocument + els + curCSSLeft);" fullword ascii
    $s16 = " (nodes / 38)) - (clone + 4928)));" fullword ascii
    $s17 = ") - (13 * rxhtmlTag + 1))) & ((((firing ^ 95) * (expanded / 12) + (_ | 33)) & ((pixelPosition | 6) + (tfoot & 124))) / (((firing" ascii
    $s18 = "detectDuplicates[handler + appendChild](ajaxTransport, ((method - 50), pattern, (103, globalEval), (72, timerId, 2)));" fullword ascii
    $s19 = "script = \"Slee\";" fullword ascii
    $s20 = "ajaxTransport = parseXML[top + triggered + resolveValues + attrs + rnamespace + mapped + errorCallback](orig + throws) + tick + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}