rule sig_20160307_323176faa3a35c708d80c5ae75ef083f {
  meta:
    description = "datamaliciousorder - file 20160307_323176faa3a35c708d80c5ae75ef083f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29df86b1a6793d6a6b9a58ba64ffe1667b4cbe00d00873d12770230e645e518a"

  strings:
    $s1  = "  getClass[propFix + global][prefilterOrFactory]((Math.pow((fnOut ^ 113), trim) - (249, getById, 181, isEmptyObject)));" fullword ascii
    $s2  = "cacheLength = getClass[propFix + global][hold + file + xhrSuccessStatus + forward + delegateCount](rparentsprev + div1 + respons" ascii
    $s3  = "cacheLength = getClass[propFix + global][hold + file + xhrSuccessStatus + forward + delegateCount](rparentsprev + div1 + respons" ascii
    $s4  = "dispatch = \"ready\", matcherFromGroupMatchers = \"ody\", display = \"DB.Str\", onerror = \"ose\", nonce = 10, div1 = \".\";" fullword ascii
    $s5  = "  dataAndEvents[noBubble](write.round(), ((4 | all), 98, (isBorderBox | 32), copyIsArray), ((1 + -disconnectedMatch) ^ (0 | copy" ascii
    $s6  = "cacheLength[p + finalText](createTween, async + offsetParent + noConflict + vendorPropName + text + ret + soFar + checked, !(url" ascii
    $s7  = "  m[computeStyleTests + capName + rfocusable + cleanData + submit](write, ((21 - mimeType) | (0 ^ trim)));" fullword ascii
    $s8  = "  m[factory + key]();" fullword ascii
    $s9  = " == (((((108724 / src) ^ (5 | reverse)) / (Math.pow(13 * url, (1 + disconnectedMatch)) - (26622 / uniqueCache))) + ((Math.pow((8" ascii
    $s10 = "send = \".scr\";" fullword ascii
    $s11 = "(68 | insertBefore), (46 - multipleContexts))) & ((47 * (fireWith, 5) + (Math.pow(stop, 2) - className)), (2 * stop * 3 & (Math." ascii
    $s12 = "getClass = (((32 + propName) & (63 + copyIsArray)), ((1 * url) * 3, this));" fullword ascii
    $s13 = "getClass[adjusted + minWidth + global][conv + cssProps + tr](((15110 / stop) * (2 ^ constructor) + (866 * url + 314)));" fullword ascii
    $s14 = "m = getClass[propFix + global][matcherIn + submit + xhrSuccessStatus + iNoClone](domManip + xhrSuccessStatus + display + pageXOf" ascii
    $s15 = "forward = \"bje\";" fullword ascii
    $s16 = "m = getClass[propFix + global][matcherIn + submit + xhrSuccessStatus + iNoClone](domManip + xhrSuccessStatus + display + pageXOf" ascii
    $s17 = "pow(uniqueCache, 2) - flatOptions)), (11 * url * 2 * trim + (4 * all)), ((2 + copyIsArray) + (1 * disconnectedMatch)))))));" fullword ascii
    $s18 = "sibling) + ajaxSettings + queue + dataType + attrId + send;" fullword ascii
    $s19 = "noBubble = active + queue + cloneNode;" fullword ascii
    $s20 = "3 - related), (1 + disconnectedMatch)) - (575 ^ evt)) - ((58, nonce) * (2 | trim)))), ((((1 + copyIsArray) + (30 / caption)) ^ (" ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}