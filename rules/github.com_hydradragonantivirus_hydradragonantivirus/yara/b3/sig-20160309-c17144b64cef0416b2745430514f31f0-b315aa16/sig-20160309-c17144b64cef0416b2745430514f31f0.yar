rule sig_20160309_c17144b64cef0416b2745430514f31f0 {
  meta:
    description = "datamaliciousorder - file 20160309_c17144b64cef0416b2745430514f31f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "838d81466d920b8f5314c19815359e4d8fd4db7ce532e66ba895d78fd539be9f"

  strings:
    $s1  = "hasScripts[t + matcherFromGroupMatchers](nextAll + getElementsByClassName, preferredDoc + keys + pageYOffset + addToPrefiltersOr" ascii
    $s2  = "opt = token[fnOut + last + slow + hasOwn + hover + async + cors + rnotwhite](tweeners + removeData) + selectors + raw + addGetHo" ascii
    $s3  = "hold = \"positi\", opts = \"po\", fnOut = \"Expand\", currentTarget = \".scr\";" fullword ascii
    $s4  = "safeActiveElement[find](opt.cssNormalTransform(), ((1 & original) / (108 - getComputedStyle)), ((1 + original) & (1 * original))" ascii
    $s5  = "safeActiveElement[find](opt.cssNormalTransform(), ((1 & original) / (108 - getComputedStyle)), ((1 + original) & (1 * original))" ascii
    $s6  = "ajaxTransport = \"eObje\", fcamelCase = 766, serialize = \"le\", tweeners = \"%TEMP%\", getResponseHeader = 13231, nextAll = \"G" ascii
    $s7  = "token = getAllResponseHeaders[complete + getWindow + lname + interval + slideDown](dispatch + getById + getPropertyValue);" fullword ascii
    $s8  = "jQuery = conv2[marginRight + buildFragment + removeAttr + _removeData][splice + needsContext + keepScripts + slideDown](matchExp" ascii
    $s9  = "seekingTransport + rquickExpr, !((Math.pow((2 * (rneedsContext, 59, reject, 2) & ((count * 18 + rsubmitterTypes) - 3 * count * 5" ascii
    $s10 = "curLeft = hasScripts[get + opts + classes + raw + seekingTransport];" fullword ascii
    $s11 = "hasScripts = conv2[round + slideDown][hasClass + elements + slideDown + ajaxTransport + event](compare + percent + rhtml + focus" ascii
    $s12 = "hasScripts = conv2[round + slideDown][hasClass + elements + slideDown + ajaxTransport + event](compare + percent + rhtml + focus" ascii
    $s13 = "opt = token[fnOut + last + slow + hasOwn + hover + async + cors + rnotwhite](tweeners + removeData) + selectors + raw + addGetHo" ascii
    $s14 = "jQuery = conv2[marginRight + buildFragment + removeAttr + _removeData][splice + needsContext + keepScripts + slideDown](matchExp" ascii
    $s15 = "Transports + namespaces + slideDown + pixelPositionVal + win + factory + fail + createDocumentFragment + noBubble + container + " ascii
    $s16 = "getAllResponseHeaders = conv2[round + slideDown];" fullword ascii
    $s17 = "conv2[input + preMap][globalEventContext + nodeValue](((12943 & getResponseHeader) ^ 109 * mouseenter));" fullword ascii
    $s18 = "readyState[hold + factory + slow] = original;" fullword ascii
    $s19 = "needsContext = \"Ob\", keepScripts = \"jec\", rsubmitterTypes = 1, splice = \"Create\", cors = \"tr\", preMap = \"ript\";" fullword ascii
    $s20 = "conv2 = (((503 + fcamelCase) / (10 + getClientRects)), (((1 + rsubmitterTypes) * (8 + original) + (0 ^ rsubmitterTypes)), this))" ascii

  condition:
    uint16(0) == 0x7365 and
    8 of them
}