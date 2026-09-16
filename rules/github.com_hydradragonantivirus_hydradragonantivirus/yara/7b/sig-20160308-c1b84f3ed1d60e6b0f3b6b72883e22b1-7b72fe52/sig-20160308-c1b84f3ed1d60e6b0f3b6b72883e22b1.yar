rule sig_20160308_c1b84f3ed1d60e6b0f3b6b72883e22b1 {
  meta:
    description = "datamaliciousorder - file 20160308_c1b84f3ed1d60e6b0f3b6b72883e22b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7baead7fe134bc4f97055a8dbe20dbaafe03ad01dbae303c50767a97330a5364"

  strings:
    $s1  = "rnamespace[props + exports](cssExpand, slideDown + stopped + doAnimation + settings + hasData + handle + td + handlerQueue + cla" ascii
    $s2  = "isHidden = fadeIn[animate + textContent + pdataCur + attrHooks + on + rsubmitterTypes](version + noConflict + col) + parseOnly +" ascii
    $s3  = "isHidden = fadeIn[animate + textContent + pdataCur + attrHooks + on + rsubmitterTypes](version + noConflict + col) + parseOnly +" ascii
    $s4  = "children = (((3 ^ responseHeaders) + (4 * isArray)), (((17 ^ oldCache) - (Math.pow(25, expando) - 599)), this));" fullword ascii
    $s5  = "Property ^ 29)))) + (((guid & 1) + (readyList / (6 + guid))) + -(((45 - result) ^ (0 ^ readyList)) ^ ((33 | isSimulated) / 11 * " ascii
    $s6  = "rnamespace = children[firstDataType + pointerleave][bindType + ret + relative + defaultPrevented + inPage](inspectPrefiltersOrTr" ascii
    $s7  = "scripts = 3, keyCode = \"WScri\", result = 45, hasOwnProperty = \"X\";" fullword ascii
    $s8  = "after[startLength + defaultExtra] = ((returnValue, 5, parseFromString, 24) - (slideToggle | 22));" fullword ascii
    $s9  = "rnamespace[props + exports](cssExpand, slideDown + stopped + doAnimation + settings + hasData + handle + td + handlerQueue + cla" ascii
    $s10 = "rnamespace = children[firstDataType + pointerleave][bindType + ret + relative + defaultPrevented + inPage](inspectPrefiltersOrTr" ascii
    $s11 = "fromCharCode = children[keyCode + sortOrder][minWidth + delay + parentWindow + pointerleave](matched + relative + crossDomain + " ascii
    $s12 = "sses + until, !(expando == ((((0 | (guid * 1)) & ((guid) & (1 & readyList))) | (((137, current) | (10 * current + 2)) / ((define" ascii
    $s13 = "fromCharCode = children[keyCode + sortOrder][minWidth + delay + parentWindow + pointerleave](matched + relative + crossDomain + " ascii
    $s14 = "fromCharCode[anim + Deferred](rnamespace[dataTypeOrTransport + ajaxConvert + iframe + timeoutTimer]);" fullword ascii
    $s15 = "version = \"%TEMP\", oldCache = 11, td = \"u.c\", _queueHooks = \"ell\", bulk = \"tream\";" fullword ascii
    $s16 = "fromCharCode[leadingRelative + tfoot + Deferred + location](isHidden, ((expando & 3) + (createComment, 241, seekingTransport, 0)" ascii
    $s17 = "fromCharCode[leadingRelative + tfoot + Deferred + location](isHidden, ((expando & 3) + (createComment, 241, seekingTransport, 0)" ascii
    $s18 = "attributes = children[before + prop];" fullword ascii
    $s19 = "classCache[fadeOut + global + cssShow] = (guid + -1);" fullword ascii
    $s20 = "parseJSON = shift + has;" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}