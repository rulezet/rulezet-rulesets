rule sig_20160308_74149ba4aee8b28f8818eb39f3d17a7c {
  meta:
    description = "datamaliciousorder - file 20160308_74149ba4aee8b28f8818eb39f3d17a7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0423b2851ec3b2bcee7c661621805038e9832738645128423855e47e355bcd1d"

  strings:
    $s1  = "sortInput[ajaxTransport](rbuggyMatches, pattern + dataTypes + dataAttr + invert + crossDomain + isSuccess + rheaders + setAttrib" ascii
    $s2  = "init[selector + overflowY + doc + processData] = ((PI ^ 1) * PI);" fullword ascii
    $s3  = "sortInput[ajaxTransport](rbuggyMatches, pattern + dataTypes + dataAttr + invert + crossDomain + isSuccess + rheaders + setAttrib" ascii
    $s4  = "- 300), (dequeue & 31), unit * 2, (letterSpacing * 4))) | (((Math.pow(rcheckableType, 2) - rts) + (17 + PI)) - ((178, rcheckable" ascii
    $s5  = ") * (udataCur - 6))) - ((mouseenter / 29) / (seekingTransport * 3 + rdashAlpha))) | ((93, div1, 257) | ((rdashAlpha | 0) + (safe" ascii
    $s6  = "ute + class2type, !((((Math.pow(((Math.pow(206, letterSpacing) - 42209), (button ^ 211), (matched / 32)), ((seekingTransport / 4" ascii
    $s7  = "el = fcamelCase[matcherIn + setMatchers + resolveValues + eq + backgroundClip + ready + href + overflow](dispatch + pos) + toArr" ascii
    $s8  = "rbrace[globalEventContext + complete][showHide + msg + ct](((233 ^ sel) * 2 * attachEvent * 2 + (curCSSLeft ^ 214)));" fullword ascii
    $s9  = "ActiveElement & 3)))) / (((parseFromString, 36, letterSpacing) * 3 * (body, 130, letterSpacing) | ((Math.pow(18, letterSpacing) " ascii
    $s10 = "sortInput = rbrace[duplicates + rxhtmlTag + completeDeferred + argument][overflowX + adjustCSS + complete](xhrSupported + inPage" ascii
    $s11 = "sortInput = rbrace[duplicates + rxhtmlTag + completeDeferred + argument][overflowX + adjustCSS + complete](xhrSupported + inPage" ascii
    $s12 = "rbrace = (((81 + attachEvent) + (30 & specialEasing)), (((8 & submit) | (61, preDispatch, 7, submit)), this));" fullword ascii
    $s13 = "qualifier = rbrace[flag + container];" fullword ascii
    $s14 = "Type) + (1 ^ PI))))) == 9));" fullword ascii
    $s15 = "pointerleave[eventHandle + reverse](el, (3 & letterSpacing));" fullword ascii
    $s16 = "while (sortInput[includeWidth + delegate + udataOld + rjsonp] < ((rdashAlpha ^ 5) | (PI & 1))) {" fullword ascii
    $s17 = "pointerleave = rbrace[outermostContext + querySelectorAll][propHooks + wrap + assert](open + context + resolveContexts + size);" fullword ascii
    $s18 = "rbrace[outermostContext + querySelectorAll][rsubmittable](((divStyle * 2 + resolve) / (12 + dequeue)));" fullword ascii
    $s19 = "pointerleave[display + disabled]();" fullword ascii
    $s20 = "leadingRelative = hide + originalOptions;" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}