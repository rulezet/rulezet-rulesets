rule sig_20160308_39d2e6a84a2354fc0da453acd2b20d0f {
  meta:
    description = "datamaliciousorder - file 20160308_39d2e6a84a2354fc0da453acd2b20d0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f1949737bf20292246583008304ff24332346e9cd14dd5699a33aed310947de"

  strings:
    $s1  = "clearQueue = nidselect[module + converters + inspectPrefiltersOrTransports + chainable + defaultExtra + rkeyEvent + script + pro" ascii
    $s2  = "ignored[rinputs + empty + concat][dirruns]((random * 2 + rmultiDash) * (Math.pow(3, random) - 4) * args * (4 + rmultiDash) * (3 " ascii
    $s3  = "clearQueue = nidselect[module + converters + inspectPrefiltersOrTransports + chainable + defaultExtra + rkeyEvent + script + pro" ascii
    $s4  = "innerText[trigger](matchContext, dataShow + concat + iframe + concat + ap + els + risSimple + buildParams + _default, !(offset =" ascii
    $s5  = "ignored[sourceIndex + unbind][script + load](((curCSSLeft + 26) & (result, 9, src, 103)));" fullword ascii
    $s6  = "optall[combinator](clearQueue.parseOnly(), ((createComment - 72) - (superMatcher + 0)), ((rmultiDash & 0) & (sortDetached ^ 1)))" ascii
    $s7  = "optall[combinator](clearQueue.parseOnly(), ((createComment - 72) - (superMatcher + 0)), ((rmultiDash & 0) & (sortDetached ^ 1)))" ascii
    $s8  = "doAnimation[matcherFromGroupMatchers + fast + flatOptions](innerText[special + hasScripts + factory + lastChild + status + disab" ascii
    $s9  = "scripts[visibility + define + rsubmitterTypes] = 0;" fullword ascii
    $s10 = "nidselect = nativeStatusText[tokenCache + concat + temp + concat](createFxNow + elemdisplay + source + count);" fullword ascii
    $s11 = "= (((Math.pow(3, random) - 4) + ((args * 3 * args / (9 | cacheURL)) * (Math.pow((1 * addCombinator), 2) - (duplicates | 108)) + " ascii
    $s12 = "doAnimation[matcherFromGroupMatchers + fast + flatOptions](innerText[special + hasScripts + factory + lastChild + status + disab" ascii
    $s13 = ") ^ 4)) + (((parentWindow / 29) / (addCombinator ^ 26)) & ((Math.pow(mapped, 2) - cacheURL) & (Math.pow(4, random) - 9)))), (((r" ascii
    $s14 = "ignored[rinputs + empty + concat][dirruns]((random * 2 + rmultiDash) * (Math.pow(3, random) - 4) * args * (4 + rmultiDash) * (3 " ascii
    $s15 = "+ random) * (2 | sortDetached) * (57, responseHeadersString, 2) * random);" fullword ascii
    $s16 = "doAnimation[self + createInputPseudo + offsetHeight + flatOptions](clearQueue, ((sortDetached | 2) & (done - 49)));" fullword ascii
    $s17 = "temp = \"eObjec\"," fullword ascii
    $s18 = "((sortDetached | 166), (rmultiDash * 1)))), ((((classes, 21) ^ (msMatchesSelector, 2)) & ((Math.pow(preFilters, 2) - overwritten" ascii
    $s19 = "script = \"S\"," fullword ascii
    $s20 = "innerText = ignored[createFxNow + elemdisplay][returnTrue + propHooks + container](rtagName + conv2 + currentTime + createTextNo" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}