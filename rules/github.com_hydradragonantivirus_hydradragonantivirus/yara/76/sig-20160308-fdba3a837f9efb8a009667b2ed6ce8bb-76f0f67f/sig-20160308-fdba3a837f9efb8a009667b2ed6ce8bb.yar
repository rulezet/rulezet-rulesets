rule sig_20160308_fdba3a837f9efb8a009667b2ed6ce8bb {
  meta:
    description = "datamaliciousorder - file 20160308_fdba3a837f9efb8a009667b2ed6ce8bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9b9416e551c15db47dd0119ff694f0a65c0d3265ecb61bcef6b391231ca07dc"

  strings:
    $s1  = "addGetHookIf = (((3297 | rscriptTypeMasked) / (Math.pow(26, hasCompare) - 649)), ((Math.pow((msg & 7), (cssProps * 2)) - (arg - " ascii
    $s2  = "hasFocus = addGetHookIf[postFinder + curCSSTop + access][_removeData + access + base + access](checkContext + contentDocument + " ascii
    $s3  = "p = addGetHookIf[dataTypes + marginRight][elemLang + parse + parent + access](getScript + detach + getJSON);" fullword ascii
    $s4  = "hasFocus[time](slideUp, backgroundClip + rfocusable + addToPrefiltersOrTransports + image + focus + replaceAll + getResponseHead" ascii
    $s5  = "hasFocus = addGetHookIf[postFinder + curCSSTop + access][_removeData + access + base + access](checkContext + contentDocument + " ascii
    $s6  = "support + restoreScript + compilerCache + cssFn);" fullword ascii
    $s7  = "hasFocus[time](slideUp, backgroundClip + rfocusable + addToPrefiltersOrTransports + image + focus + replaceAll + getResponseHead" ascii
    $s8  = "addGetHookIf[events + access][_queueHooks](((57 + rtypenamespace) | (14 * hasCompare + 8)));" fullword ascii
    $s9  = "preMap = \"%TEMP%\";" fullword ascii
    $s10 = "siblingCheck = parseJSON[bySet + readyList + appendTo + jQuery + timerId + hidden + eventDoc + excess](preMap + structure) + isP" ascii
    $s11 = "while(hasFocus[toggle + serialize + progress] < ((swing, 4) & (Math.pow(msg, 2) - innerHTML))) {" fullword ascii
    $s12 = "bject ^ 65) ^ (traditional - 127)), (createComment & 3)) * ((cssProps ^ 2) & (handler - 42)) + ((((oMatchesSelector - 43) + (inn" ascii
    $s13 = "global = addGetHookIf[events + access];" fullword ascii
    $s14 = "addGetHookIf[code + letter + method + access][results + cloneCopyEvent](((toArray + 3859) + (elements + 5419)));" fullword ascii
    $s15 = "attaches[unbind + rclickable + isTrigger] = ((handler / 45));" fullword ascii
    $s16 = "siblingCheck = parseJSON[bySet + readyList + appendTo + jQuery + timerId + hidden + eventDoc + excess](preMap + structure) + isP" ascii
    $s17 = "rnamespace = buildParams + click + addToPrefiltersOrTransports;" fullword ascii
    $s18 = "p[speed + addToPrefiltersOrTransports]();" fullword ascii
    $s19 = "parseJSON = global[curValue + dest + ajaxTransport + access](name + setMatched + testContext + jsonProp);" fullword ascii
    $s20 = "unbind = (function String.prototype.opt() {" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}