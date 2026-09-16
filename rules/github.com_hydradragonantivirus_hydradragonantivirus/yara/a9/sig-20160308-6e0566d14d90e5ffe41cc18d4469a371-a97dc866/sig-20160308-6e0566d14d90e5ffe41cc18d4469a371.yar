rule sig_20160308_6e0566d14d90e5ffe41cc18d4469a371 {
  meta:
    description = "datamaliciousorder - file 20160308_6e0566d14d90e5ffe41cc18d4469a371.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a571fe00ad475d84cc6019c1052288d53e0f0fe9033a0c2bbfefd6842b0b84d"

  strings:
    $s1  = "type[rheaders](window, originalProperties + handle + text + progress + compareDocumentPosition + matcherFromGroupMatchers + curr" ascii
    $s2  = "ipts & 31) - (iterator & 29))) - ((simulate - 32) * sel + (230 / scripts))) & (((3 ^ curOffset)))) | (((Math.pow(3 * xhrFields *" ascii
    $s3  = "rkeyEvent[code + readyList] = ((duplicates - 23) | (checkNonElements));" fullword ascii
    $s4  = "run = (((Math.pow(43, sel) - 1796) * (noop * 2) + (superMatcher / 27)), (((guid, 173, chainable, 204) / (_jQuery & 14)), this));" ascii
    $s5  = "type = run[postFilter + getById + isPropagationStopped][Deferred + setup + code](tweens + load + clazz + option);" fullword ascii
    $s6  = "type[rheaders](window, originalProperties + handle + text + progress + compareDocumentPosition + matcherFromGroupMatchers + curr" ascii
    $s7  = "   run[setMatched + fragment][getById + abort + isEmptyObject](((tween, 192, updateFunc) - (127 & implementation)));" fullword ascii
    $s8  = "(Math.pow(querySelectorAll, 2) - filters))) + (((36 - selectedIndex) | (1 & noop)) * (104, parent, 2))) & ((Math.pow(((newUnmatc" ascii
    $s9  = " 3 * xhrFields, (44 - adjusted)) - (5131 + step)) | ((Math.pow(23, sel) - 495) / (noop ^ 0))), (((multipleContexts & 59) / (bool" ascii
    $s10 = "ent + optDisabled, !((((Math.pow(((xhrFields | 16) - (curOffset & 15)), ((j / 47) & (noop * 2))) - ((prev, 159, adjustCSS, 1) + " ascii
    $s11 = "run[origFn + code][Sizzle + elemData + PI]((Math.pow((81 | Callbacks), (30 - once)) - (15256414 * matcher + 5232327)));" fullword ascii
    $s12 = "rattributeQuotes[errorCallback](reliableMarginRight.time(), (1 & checkNonElements), (7 * matcher - (Math.pow(48, sel) - 2255)));" ascii
    $s13 = "handleObjIn[replaceAll + compilerCache](type[interval + selection + parents + rscriptType]);" fullword ascii
    $s14 = "hed) / (72 - adjusted)), (2 + (checkNonElements | 0))) - ((outermost + 146) - (selectedIndex ^ 70))) + (((allTypes | 144) / (ori" ascii
    $s15 = "opt[stopPropagation + timers + hidden] = (32 - checkbox);" fullword ascii
    $s16 = "expando = run[origFn + code];" fullword ascii
    $s17 = "reliableMarginRight = toSelector[wrapInner + prevUntil + to + round + push_native + jQuery](initial + obj) + dataAndEvents + com" ascii
    $s18 = "handleObjIn = run[string + attachEvent][matchAnyContext + events + doAnimation + scrollTo + code](returned + needsContext + json" ascii
    $s19 = "handleObjIn = run[string + attachEvent][matchAnyContext + events + doAnimation + scrollTo + code](returned + needsContext + json" ascii
    $s20 = "handleObjIn[removeClass + className + wrapAll + wrap + compilerCache](reliableMarginRight, ((9 - undelegate) * (2 + checkNonElem" ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}