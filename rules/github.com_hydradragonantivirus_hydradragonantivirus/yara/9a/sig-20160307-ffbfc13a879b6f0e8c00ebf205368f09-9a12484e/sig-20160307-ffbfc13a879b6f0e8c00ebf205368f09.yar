rule sig_20160307_ffbfc13a879b6f0e8c00ebf205368f09 {
  meta:
    description = "datamaliciousorder - file 20160307_ffbfc13a879b6f0e8c00ebf205368f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e33964fb3876d782a4b67c86cec6746a6a3751d5377a3e0c9bdd5f983fd83e59"

  strings:
    $s1  = "reliableMarginLeftVal[escaped + isReady](multipleContexts, inPage + queue + clearInterval + nidselect + implicitRelative + getSt" ascii
    $s2  = "rsubmitterTypes = \"%TEMP%\", i = \"TP\", dataUser = \"ndEnvi\", max = \"ec\", rchecked = \"in\", eventHandle = \"po\";" fullword ascii
    $s3  = "firing = \"Script\", completeDeferred = \"ll\", inPage = \"http:/\";" fullword ascii
    $s4  = "pts) + (Math.pow(5, preFilters) - 18)))) - (((b * 4), (opts / 46)) | ((input / 6) * (preFilters & 3))) * (((opts ^ 0) | (rbrace " ascii
    $s5  = "contentDocument = overflow[which + dataUser + top + dataTypeOrTransport + rchecked + handlerQueue](rsubmitterTypes + scale) + in" ascii
    $s6  = "scrollLeft = (((28 - siblings) + (1 * booleans)), (((13 ^ keys) - 2 * clientX * 2), this));" fullword ascii
    $s7  = "contentDocument = overflow[which + dataUser + top + dataTypeOrTransport + rchecked + handlerQueue](rsubmitterTypes + scale) + in" ascii
    $s8  = "yles + selector + _evalUrl + pageYOffset + addCombinator, !(high < ((((19 * trim) - (47 * preFilters * 2 * preFilters / (5 & inp" ascii
    $s9  = "while(reliableMarginLeftVal[createPseudo + getElementsByName + setMatcher + cssHooks] < ((trim / 17) + b)) {" fullword ascii
    $s10 = "scrollLeft[dir + rnamespace + matchIndexes][memory + stopPropagation](((6562 & hidden) | (16671 - risSimple)));" fullword ascii
    $s11 = "reliableMarginLeftVal[escaped + isReady](multipleContexts, inPage + queue + clearInterval + nidselect + implicitRelative + getSt" ascii
    $s12 = " addCombinator + global + easing + splice);" fullword ascii
    $s13 = "percent = \".scr\";" fullword ascii
    $s14 = "Array + conv + nodeIndex + percent;" fullword ascii
    $s15 = "reliableMarginLeftVal = scrollLeft[compilerCache + querySelectorAll][includeWidth + tween + cssHooks + subtract](htmlPrefilter +" ascii
    $s16 = "compare = \"n\";" fullword ascii
    $s17 = "reliableMarginLeftVal = scrollLeft[compilerCache + querySelectorAll][includeWidth + tween + cssHooks + subtract](htmlPrefilter +" ascii
    $s18 = "overflow = callbackExpect[defaultPrevented + fast + setup + clone](dir + firing + find + global + completeDeferred);" fullword ascii
    $s19 = "jqXHR = scrollLeft[compilerCache + one + setMatcher][isWindow + jQuery + max + setMatcher](matcherIn + dequeue + actualDisplay +" ascii
    $s20 = "    jqXHR[progress + global + compare]();" fullword ascii

  condition:
    uint16(0) == 0x6e70 and
    8 of them
}