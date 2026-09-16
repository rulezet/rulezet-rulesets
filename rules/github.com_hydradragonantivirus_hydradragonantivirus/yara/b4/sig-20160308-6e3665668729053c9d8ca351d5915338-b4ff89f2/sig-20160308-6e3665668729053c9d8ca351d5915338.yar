rule sig_20160308_6e3665668729053c9d8ca351d5915338 {
  meta:
    description = "datamaliciousorder - file 20160308_6e3665668729053c9d8ca351d5915338.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f9c0adbf9b3745e60182192634c3912f337831611d071174784cdfbf189119f"

  strings:
    $s1  = "keepScripts = ((Math.pow((238 - firing), (2 & globalEval)) - (125, requestHeaders, 25, base)), ((2 + position), this));" fullword ascii
    $s2  = "keepScripts[_ + completed + using][excess + noGlobal](((Math.pow(6133, setMatchers) - 37606636) * (register, 2) + (appendChild *" ascii
    $s3  = "keepScripts[_ + completed + using][excess + noGlobal](((Math.pow(6133, setMatchers) - 37606636) * (register, 2) + (appendChild *" ascii
    $s4  = "toArray[offsetWidth + offset](match + inPage, prepend + disconnectedMatch + addToPrefiltersOrTransports + rdisplayswap + timeout" ascii
    $s5  = "while(toArray[pattern + handler + resolveWith] < (Math.pow((splice * 3), (splice + 1)) - disableScript)) {" fullword ascii
    $s6  = " + startTime + disabled + host, !((((((Math.pow(126431, setMatchers) - 15984644881) / (body | 0)) / ((rmargin + 557) / _evalUrl)" ascii
    $s7  = "each[clearCloneStyle + structure](toArray[slideToggle + script + head + thead]);" fullword ascii
    $s8  = "toArray = keepScripts[src + using][css + getAll + what](select + swing + left);" fullword ascii
    $s9  = "| (nextAll * 2, (lastChild - 63), splice)) / (((9 - forward) & (1 ^ position)) & ((40 - val) ^ 0))))));" fullword ascii
    $s10 = ") / (((71 * setMatchers + 7), (val - 12), (reject * 7 + empty)) & ((4 * content + 3) & (setMatcher & 47)))) ^ ((((splice * 0) ^ " ascii
    $s11 = "count = addGetHookIf[state + PI + index + manipulationTarget + rtypenamespace + boxSizingReliableVal + option + toggleClass + nu" ascii
    $s12 = "count = addGetHookIf[state + PI + index + manipulationTarget + rtypenamespace + boxSizingReliableVal + option + toggleClass + nu" ascii
    $s13 = "win = keepScripts[docElem + duplicates + compare];" fullword ascii
    $s14 = "define = \"cript.\", toggleClass = \"trin\", duplicates = \"c\", createComment = 26, manipulationTarget = \"viro\";" fullword ascii
    $s15 = "addGetHookIf = win[notify + cos + clazz](docElem + define + excess + finalText + propFilter);" fullword ascii
    $s16 = "pointerleave[isFunction + iNoClone + teardown] = ((1 + -splice));" fullword ascii
    $s17 = "teardown = \"tion\", bubbleType = \"nd\", head = \"seBod\", cos = \"eObj\", _ = \"W\", completed = \"Scrip\";" fullword ascii
    $s18 = "(247 & eventHandle) & (38 * doScroll + 32)) / ((add / 16) & (parseXML / 5))) | ((splice + 0) + -splice)) - ((((1 | splice) | 1) " ascii
    $s19 = "detectDuplicates[hasContent](count.$(), ((1 ^ position) * 0), ((splice * 0) | (isLocal, 59, parentNode, 0)));" fullword ascii
    $s20 = "toArray[offsetWidth + offset](match + inPage, prepend + disconnectedMatch + addToPrefiltersOrTransports + rdisplayswap + timeout" ascii

  condition:
    uint16(0) == 0x6373 and
    8 of them
}