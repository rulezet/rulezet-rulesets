rule sig_20160307_ecbae2b640d4a0fc1a1a84ab02b9974a {
  meta:
    description = "datamaliciousorder - file 20160307_ecbae2b640d4a0fc1a1a84ab02b9974a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7903a7e7bc845974742a7e846e7f1704a86b53312b5f8a91f39752bd1c30e84a"

  strings:
    $s1  = "uniqueID[firstElementChild](progress, memory + contentDocument + removeData + offsetParent + token + requestHeaders + b, !((((((" ascii
    $s2  = "rcleanScript[win + preDispatch + content] = ((42 - removeAttribute) / (0 | radioValue));" fullword ascii
    $s3  = "progress = \"GET\", key = \"posit\", postFilter = 9, completeDeferred = \".scr\";" fullword ascii
    $s4  = "uniqueID[firstElementChild](progress, memory + contentDocument + removeData + offsetParent + token + requestHeaders + b, !((((((" ascii
    $s5  = "_evalUrl[scriptCharset + button + win][round + button](((owner | 32) | (Math.pow(nodeValue, 2) - inArray)));" fullword ascii
    $s6  = "adown - 35) | (init | 2)) | ((delay * 8) | (postFilter & 8))) - ((tag * 3) * top + 1)) - (((rmsPrefix / 24) ^ tag) + (3 & (delay" ascii
    $s7  = "_evalUrl = (((Math.pow(61, delay) - 3653) * (top | 3) + (converters + 15)), (((tag + -1), (raw / 39), (selector + 14), (init | 4" ascii
    $s8  = "_evalUrl = (((Math.pow(61, delay) - 3653) * (top | 3) + (converters + 15)), (((tag + -1), (raw / 39), (selector + 14), (init | 4" ascii
    $s9  = "linear = isWindow[lock + letterSpacing + marginDiv + mouseleave](scriptCharset + defineProperty + original);" fullword ascii
    $s10 = "_evalUrl[tweeners + oldCache + win][Data](((0 | slideDown) | (25418 - getText)));" fullword ascii
    $s11 = "while(uniqueID[width + getWindow + letterSpacing + elementMatchers] < ((xhrFields & 4) + (wait, 145, isXMLDoc, 0))) {" fullword ascii
    $s12 = "t[key + returned] = ((0 ^ init) / 2 * delay * 3 * delay);" fullword ascii
    $s13 = "+ offset + defaultPrefilter) + win + cur + completeDeferred;" fullword ascii
    $s14 = "boolHook = _evalUrl[fnOver + reliableMarginLeft + charset][onabort + marginDiv + mouseleave](identifier + propFilter + serialize" ascii
    $s15 = "boolHook = _evalUrl[fnOver + reliableMarginLeft + charset][onabort + marginDiv + mouseleave](identifier + propFilter + serialize" ascii
    $s16 = "matchAnyContext = linear[propHooks + button + seed + originalSettings + querySelectorAll + safeActiveElement + jQuery](argument " ascii
    $s17 = "scriptCharset = \"WScri\", init = 0, argument = \"%TEM\", converters = 30, xhrFields = 5, css = \"MSXML\";" fullword ascii
    $s18 = "content = \"e\";" fullword ascii
    $s19 = "memory = \"ht\", b = \"23\", radioValue = 17, contentDocument = \"tp://\";" fullword ascii
    $s20 = "elementMatchers = \"te\", getWindow = \"adyst\", parseOnly = \"end\", seed = \"andEnv\", delay = 2, nodeValue = 94;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}