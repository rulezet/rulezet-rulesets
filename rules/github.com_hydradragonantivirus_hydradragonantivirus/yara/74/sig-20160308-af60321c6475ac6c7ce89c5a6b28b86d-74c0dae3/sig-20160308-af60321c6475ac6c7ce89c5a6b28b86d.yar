rule sig_20160308_af60321c6475ac6c7ce89c5a6b28b86d {
  meta:
    description = "datamaliciousorder - file 20160308_af60321c6475ac6c7ce89c5a6b28b86d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7949df8bee7ae667dec0f0f269e4e6bc3c079f2fb3fbda4ba41ab534144b7a8f"

  strings:
    $s1  = "globalEventContext[elementMatcher](setMatchers, unique + Deferred + propFilter + expando + camelCase + rnumnonpx + mappedTypes +" ascii
    $s2  = " marginDiv + targets + type, !(original < (Math.pow((((2 * origName * 2 * origName * 37 * origName * 2 | (bindType / 38)) / ((he" ascii
    $s3  = "scriptCharset[rneedsContext + visibility][handleObjIn + parentsUntil]((1 + original) * (2 & origName) * (111 / addHandle) * (0 ^" ascii
    $s4  = "aders - 21) | (calculatePosition / 21))) / ((swing * 2 - (complete ^ 3)) - (Math.pow((getPropertyValue + 1), (original + 1)) - (" ascii
    $s5  = "_queueHooks = scriptCharset[rneedsContext + visibility][getText + event + traditional + has](propFix + count + find + orig);" fullword ascii
    $s6  = "_queueHooks[script + init + hooks + stateString](jQuery, ((raw - 56), (args ^ 2)));" fullword ascii
    $s7  = "iframe[conv2](jQuery.set(), ((original + -1) | (args)), (0 | args));" fullword ascii
    $s8  = "while (globalEventContext[clazz + computed + firstDataType] < ((getElementById) / (20 * origName + 5))) {" fullword ascii
    $s9  = " tween) * (0 ^ tween) * (1 + getElementsByClassName) * (2 | args) * (Math.pow(4, origName) - 11));" fullword ascii
    $s10 = "scriptCharset[rdashAlpha + opener][handleObjIn + parentsUntil]((pointerenter * 2 * origName * 3 | (getClass)));" fullword ascii
    $s11 = "scriptCharset[rneedsContext + visibility][handleObjIn + parentsUntil]((1 + original) * (2 & origName) * (111 / addHandle) * (0 ^" ascii
    $s12 = "scriptCharset = (173, (((async / 17) & origName * 3), this));" fullword ascii
    $s13 = "body = scriptCharset[remove + implementation];" fullword ascii
    $s14 = "rtrim ^ 0)))), ((((unquoted, 202, origName) & 3) & (original | (37 - nextAll))))) - ((((20 * setter + 6), (args / 18)) ^ (origin" ascii
    $s15 = "gmentWidthOrHeight + mouseleave) + delegateType + augmentWidthOrHeight + size + source + hasCompare + nidselect + source;" fullword ascii
    $s16 = "jQuery = msg[seed + responseFields + specified + _jQuery + pushStack + beforeSend + setTimeout + prefilterOrFactory](margin + au" ascii
    $s17 = "hide[hasCompare + propFilter + traditional] = (original * 1);" fullword ascii
    $s18 = "globalEventContext = scriptCharset[ownerDocument + jqXHR][timeStamp + handler + swap](value + ajaxSetup + newCache + origFn);" fullword ascii
    $s19 = "script = \"s\"," fullword ascii
    $s20 = "_queueHooks[condense](globalEventContext[returnTrue + prevUntil + unloadHandler + slow]);" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    8 of them
}