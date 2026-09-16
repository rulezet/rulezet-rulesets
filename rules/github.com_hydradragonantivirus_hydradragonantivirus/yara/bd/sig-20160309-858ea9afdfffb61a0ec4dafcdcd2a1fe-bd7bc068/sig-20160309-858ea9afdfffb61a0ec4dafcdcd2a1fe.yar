rule sig_20160309_858ea9afdfffb61a0ec4dafcdcd2a1fe {
  meta:
    description = "datamaliciousorder - file 20160309_858ea9afdfffb61a0ec4dafcdcd2a1fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "918a4379b8549f3f138960036dce5e7afc4301ae1a18db1e1220753d3cdb8175"

  strings:
    $x1  = "div[delay + emptyStyle + tabIndex](preMap, parseXML + context + jsonp + onerror + documentIsHTML + optgroup + allTypes + respons" ascii
    $s2  = "/ Symbol) / (Math.pow(21, attrHooks) - 401)) - (attrHooks * 7 * attrHooks * 3 / (lname ^ 2)))) + (((Math.pow((Math.pow(target, 2" ascii
    $s3  = ") - returnTrue), (1 ^ blur)) - (37043 - eased)), (0 | (lname | 4))) ^ ((blur * 3 * blur * 2 & (prop / 22)) - ((compareDocumentPo" ascii
    $s4  = "e + ownerDocument + parsed + invert + compile + urlAnchor + timeStamp, !(once < ((((25 - resolve) / (1 * attrHooks)) ^ (((13600 " ascii
    $s5  = "parentsUntil = ((Math.pow((71 ^ firstChild), (4 - attrHooks)) - (Math.pow(24363, attrHooks) - 593529110)), (((rfocusMorph | 4) ^" ascii
    $s6  = "createElement[nonce](arr.nodes(), ((rclickable & 62) - (version + 33)), (mouseHooks / (21 & clientLeft)));" fullword ascii
    $s7  = "parentsUntil[options + addHandle][pdataCur + radio]((2 * attrHooks + 1) * (dataPriv - 38) * (lname * 3) * (Math.pow(blur, 2) - q" ascii
    $s8  = "parentsUntil[options + addHandle][pdataCur + radio]((2 * attrHooks + 1) * (dataPriv - 38) * (lname * 3) * (Math.pow(blur, 2) - q" ascii
    $s9  = "target = 116;" fullword ascii
    $s10 = "div[delay + emptyStyle + tabIndex](preMap, parseXML + context + jsonp + onerror + documentIsHTML + optgroup + allTypes + respons" ascii
    $s11 = "div = parentsUntil[resolveWith + rcheckableType][getAllResponseHeaders + colgroup + emptyStyle + oldfire](size + msg + disabled " ascii
    $s12 = "div = parentsUntil[resolveWith + rcheckableType][getAllResponseHeaders + colgroup + emptyStyle + oldfire](size + msg + disabled " ascii
    $s13 = "rsingleTag = div[valHooks + get + checkDisplay + selector];" fullword ascii
    $s14 = "lastChild[host + pointerenter]();" fullword ascii
    $s15 = "ualifier) * (2 + blur) * 2 * (mouseHooks | 5) * (valueIsBorderBox - 9));" fullword ascii
    $s16 = "iframe[callbackContext + adown + code](arr, ((46 - flag) ^ (1 + -lname)));" fullword ascii
    $s17 = "dataFilter = \"t.She\", onerror = \"h\", size = \"MS\";" fullword ascii
    $s18 = "iframe = parentsUntil[rsubmittable + serialize][teardown + defineProperty + bind](setMatchers + uid + cached);" fullword ascii
    $s19 = "get = \"spo\", resolve = 19, uid = \".\";" fullword ascii
    $s20 = "msg = \"XML2.X\", host = \"cl\", firstChild = 227, insertBefore = \"P\";" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}