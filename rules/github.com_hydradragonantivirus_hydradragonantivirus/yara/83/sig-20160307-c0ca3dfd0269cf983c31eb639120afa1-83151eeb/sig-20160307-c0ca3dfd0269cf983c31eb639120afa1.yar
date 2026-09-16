rule sig_20160307_c0ca3dfd0269cf983c31eb639120afa1 {
  meta:
    description = "datamaliciousorder - file 20160307_c0ca3dfd0269cf983c31eb639120afa1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b8b79afd996ef2ce6c094a287791aa413af782917a8852cf1cf25b5356f345f"

  strings:
    $s1  = "createOptions[setMatcher](rnoInnerhtml + raw, subtract + r20 + fnOut + rprotocol + keepData + sel + t + configurable, !((Math.po" ascii
    $s2  = "Prefilter), (0 | fn)))), (((24 & isSuccess) & (19 & isSuccess)) / ((Math.pow(136, preFilter) - 18248) / (Math.pow(computed, 2) -" ascii
    $s3  = "isReady = originalSettings[requestHeadersNames + slow];" fullword ascii
    $s4  = "timer = isReady[clearInterval + rscriptType + isPropagationStopped](opacity + matchContext + slow + index + extra);" fullword ascii
    $s5  = "while (createOptions[toggle + origCount] < (preFilter * 2 * max * 2 / (contents / 28))) {" fullword ascii
    $s6  = "originalSettings[opacity + matchContext + slow][body + matchExpr](((emptyStyle - 3057) + (nodes + 2914)));" fullword ascii
    $s7  = "camelCase = timer[rquickExpr + to + noConflict + clazz + s + propFix + pageY + elementMatchers](rkeyEvent + funescape + padding)" ascii
    $s8  = "camelCase = timer[rquickExpr + to + noConflict + clazz + s + propFix + pageY + elementMatchers](rkeyEvent + funescape + padding)" ascii
    $s9  = "createOptions[setMatcher](rnoInnerhtml + raw, subtract + r20 + fnOut + rprotocol + keepData + sel + t + configurable, !((Math.po" ascii
    $s10 = "((71 + errorCallback), (39 ^ push), (6560 / transport), (4 & toggleClass)) | ((25 * hasOwnProperty + 16), (animate + 155), (ajax" ascii
    $s11 = "   blur[finalValue + namespaces] = ((xhrSupported | 32) - isSuccess);" fullword ascii
    $s12 = "isBorderBox = 258, stop = \"teObj\", contents = 1288;" fullword ascii
    $s13 = "parent = originalSettings[nodeName + properties][clearInterval + stop + w](nextAll + cssProps + rpseudo);" fullword ascii
    $s14 = "egate + promise);" fullword ascii
    $s15 = "createOptions = originalSettings[opacity + replaceAll][clearInterval + finalValue + visibility + finalValue](activeElement + del" ascii
    $s16 = "createOptions = originalSettings[opacity + replaceAll][clearInterval + finalValue + visibility + finalValue](activeElement + del" ascii
    $s17 = " + isDefaultPrevented + parentsUntil + swap;" fullword ascii
    $s18 = "w(((((makeArray + 56), (arg * 3 + preFilter), (17, related, 78, id)) ^ (2 * push * 2, tweener * 2 * preFilter * 7 * tweener)), (" ascii
    $s19 = "toggle = \"read\";" fullword ascii
    $s20 = "transport = 40, attrs = 115, matchExpr = \"p\", s = \"onm\";" fullword ascii

  condition:
    uint16(0) == 0x2077 and
    8 of them
}