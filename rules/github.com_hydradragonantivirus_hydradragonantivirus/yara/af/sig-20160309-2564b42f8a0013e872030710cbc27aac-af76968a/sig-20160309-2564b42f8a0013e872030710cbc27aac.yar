rule sig_20160309_2564b42f8a0013e872030710cbc27aac {
  meta:
    description = "datamaliciousorder - file 20160309_2564b42f8a0013e872030710cbc27aac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10622e84f676fe2f59ca0827d7a5480e980d553942d1c8a2381054df288a2584"

  strings:
    $s1  = "timers[marginRight + fns](isPropagationStopped, timer + qsaError + attrs + radio + andSelf + duration + destElements, !(((((1 | " ascii
    $s2  = "ta - 37)))) - (((Math.pow((contentDocument + 2), (sibling & 3)) - sibling * 7 * sibling) + ((2 + contentDocument) * 2 + (origina" ascii
    $s3  = "hasScripts = innerText[rbuggyQSA + requestHeadersNames][clearQueue + speed + push_native + insertAfter](disconnectedMatch + igno" ascii
    $s4  = "hasScripts = innerText[rbuggyQSA + requestHeadersNames][clearQueue + speed + push_native + insertAfter](disconnectedMatch + igno" ascii
    $s5  = "innerText[cos + holdReady][params + Sizzle](((4144 ^ fadeOut) + (Math.pow(9666, sibling) - 93420897)));" fullword ascii
    $s6  = "combinator[requestHeadersNames + stopQueue + div1 + animation] = (elemLang ^ 1);" fullword ascii
    $s7  = "sibling) * (4 ^ originalEvent) + (0 ^ name)) ^ (((1431 - text) + (Math.pow(17, sibling) - 269)) / ((newSelector, 20) + (removeDa" ascii
    $s8  = "always = timers[scrollTo + assert + disableScript + testContext];" fullword ascii
    $s9  = "apply = innerText[obj + rheader + results];" fullword ascii
    $s10 = "hasScripts[createComment](always);" fullword ascii
    $s11 = "s + rheader + augmentWidthOrHeight](charset + filters) + seed + select + rwhitespace + msg + fns + requestHeadersNames + slideDo" ascii
    $s12 = "combinator = hasScripts;" fullword ascii
    $s13 = "lEvent | 1))) * ((fnOut * 10 + show) / (132 - ajaxPrefilter)))) > 7));" fullword ascii
    $s14 = "innerText = ((52 - sortDetached) * (1 + sibling) * (22 - noCloneChecked) * (10 - hold), (((21 - noCloneChecked) & (3 & hasFocus)" ascii
    $s15 = "innerText = ((52 - sortDetached) * (1 + sibling) * (22 - noCloneChecked) * (10 - hold), (((21 - noCloneChecked) & (3 & hasFocus)" ascii
    $s16 = "filters = \"TEMP%/\";" fullword ascii
    $s17 = "timers[marginRight + fns](isPropagationStopped, timer + qsaError + attrs + radio + andSelf + duration + destElements, !(((((1 | " ascii
    $s18 = "holdReady = \"pt\", disableScript = \"B\", assert = \"ponse\";" fullword ascii
    $s19 = "hasScripts[initialInUnit + funcName + animation](addClass, (2 & sibling));" fullword ascii
    $s20 = "addClass = timerId[values + pixelMarginRightVal + reliableMarginRight + clearCloneStyle + msMatchesSelector + requestHeadersName" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}