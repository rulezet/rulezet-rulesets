rule sig_20160309_06cdbc1ce5b420b3b356d7ac2818a93b {
  meta:
    description = "datamaliciousorder - file 20160309_06cdbc1ce5b420b3b356d7ac2818a93b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b7f8bdc2b61390d5094e05aab2ea1c2bcae389e5983952c1d17c9aa1a6aefca"

  strings:
    $x1  = "nidselect[until](classCache, lastChild + grep + Expr + parent + hide + capName + Sizzle + iNoClone + matchAnyContext + rlocalPro" ascii
    $s2  = "tokens[host](scrollLeft.hasCompare(), ((stopQueue / 49) | (actualDisplay + -1)), ((cleanData, 1) * stopQueue));" fullword ascii
    $s3  = "tocol + duplicates + prepend + ajax + easing + submit + offsetWidth + targets + tfoot, !(((((22 / disableScript) * (0 | isXMLDoc" ascii
    $s4  = ") * (0 | isXMLDoc) * (1 | method) | ((3 * isXMLDoc) + (30 - contentDocument))) - (Math.pow(((0 | xhrFields) / 40), ((parentWindo" ascii
    $s5  = "nidselect = stopped[matcherFromTokens + tfoot][clearTimeout + appendChild + modified + tfoot](t + elementMatchers + addToPrefilt" ascii
    $s6  = "host = responseHeaders;" fullword ascii
    $s7  = "border[iNoClone + head]();" fullword ascii
    $s8  = "getClass = rCRLF[byElement + matches + appendChild + dest + ajaxTransport](createPseudo + bulk + Deferred);" fullword ascii
    $s9  = "lastChild = \"http\", bulk = \"ipt.Sh\", removeProp = 21, contentDocument = 28, globalEval = \"ADOD\", prevUntil = \"ty\";" fullword ascii
    $s10 = "stopped = (((Math.pow(92, isXMLDoc) - 8370), (escaped / 44), (testContext - 9), (returnValue, 276)), (isXMLDoc * (2 ^ stopQueue)" ascii
    $s11 = "nidselect = stopped[matcherFromTokens + tfoot][clearTimeout + appendChild + modified + tfoot](t + elementMatchers + addToPrefilt" ascii
    $s12 = "stopped[curLeft + end][namespaces + key](((fire / 29), (elemData | 135), (timeout + 14702)));" fullword ascii
    $s13 = "stopped = (((Math.pow(92, isXMLDoc) - 8370), (escaped / 44), (testContext - 9), (returnValue, 276)), (isXMLDoc * (2 ^ stopQueue)" ascii
    $s14 = "scrollLeft = getClass[round + timer + getElementsByName + subordinate + origFn + clazz + events](postDispatch + xhr) + position " ascii
    $s15 = "scrollLeft = getClass[round + timer + getElementsByName + subordinate + origFn + clazz + events](postDispatch + xhr) + position " ascii
    $s16 = "not = 31, dispatch = \"write\", position = \"a\", getElementsByName = \"dEnvir\";" fullword ascii
    $s17 = "head = \"pen\";" fullword ascii
    $s18 = "style[rinputs + cssExpand]();" fullword ascii
    $s19 = "border = stopped[curLeft + end][clearTimeout + finalText + rbrace + tfoot](globalEval + scrollTop + msFullscreenElement + err);" fullword ascii
    $s20 = "border[fast + keepData + setTimeout + ajax](scrollLeft, ((removeProp / 21) + (notifyWith / 49)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}