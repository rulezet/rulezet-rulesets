rule sig_20160307_e24b40fe129b6c2397417c07f1546e20 {
  meta:
    description = "datamaliciousorder - file 20160307_e24b40fe129b6c2397417c07f1546e20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59460eade9827ebd5316132c819b8a32992a07e404d02d7a683d6dc643f1f39b"

  strings:
    $s1  = "isImmediatePropagationStopped[complete + writable][postMap + siblings](((pageXOffset & 125) | (temp - 43)));" fullword ascii
    $s2  = "pop[activeElement + parsed](firingIndex + concat, getWidthOrHeight + evt + tweeners + childNodes + noCloneChecked + tweens + cou" ascii
    $s3  = "hooks = replaceAll[size + parseXML + close + computed + rnamespace + qsaError + propFilter](getAll + ridentifier) + ifModified +" ascii
    $s4  = "isImmediatePropagationStopped[thead + html][preferredDoc](((createPseudo + 2866) - (remove * 33 + completeDeferred)));" fullword ascii
    $s5  = "hooks = replaceAll[size + parseXML + close + computed + rnamespace + qsaError + propFilter](getAll + ridentifier) + ifModified +" ascii
    $s6  = "defaultView[inspect + sort + setMatcher + curOffset](hooks, (rcleanScript - 27));" fullword ascii
    $s7  = "qsaError = \"Stri\", tweens = \"w-fs.\", concat = \"T\", activeElement = \"o\", temp = 43, async = \".scr\";" fullword ascii
    $s8  = "pop = isImmediatePropagationStopped[thead + html][attrHooks + rootjQuery + scrollTop](offset + setMatchers + curElem);" fullword ascii
    $s9  = " cssShow), ((8170 / temp) + (23 * keepData + 6)), ((dest, 52, cssShow) ^ 0)) + (remove / 27)))));" fullword ascii
    $s10 = "nt + hasData + origFn + structure + bool + last, !(7 == ((((Math.pow((checkDisplay / 33), keepData) - (256 | nType)) - ((0 | tes" ascii
    $s11 = "replaceAll = rbuggyQSA[dataFilter + when + documentElement + wrapInner](prependTo + getPropertyValue + raw + firing + original);" ascii
    $s12 = "defaultView[head](pop[isLocal + postDispatch + rmsPrefix]);" fullword ascii
    $s13 = "isImmediatePropagationStopped = (((6860 / optall) - (10 | success)), ((0 ^ cssShow), this));" fullword ascii
    $s14 = "rbuggyQSA = isImmediatePropagationStopped[complete + writable];" fullword ascii
    $s15 = "isArray[resolveValues](hooks.preFilters(), ((docElem) & (217, expand, 177, nType)), ((37 ^ camel) - (Math.pow(38, keepData) - 13" ascii
    $s16 = "isArray[resolveValues](hooks.preFilters(), ((docElem) & (217, expand, 177, nType)), ((37 ^ camel) - (Math.pow(38, keepData) - 13" ascii
    $s17 = "domManip[html + outermost] = ((Math.pow(11, keepData) - 109) - (newCache - 10));" fullword ascii
    $s18 = "head = \"write\"," fullword ascii
    $s19 = "defaultView = isImmediatePropagationStopped[has + linear][dataFilter + removeAttr + triggerHandler](doScroll + expando + animate" ascii
    $s20 = "maxWidth[mapped + unloadHandler + udataOld] = ((global * 13 + querySelectorAll), 0);" fullword ascii

  condition:
    uint16(0) == 0x7571 and
    8 of them
}