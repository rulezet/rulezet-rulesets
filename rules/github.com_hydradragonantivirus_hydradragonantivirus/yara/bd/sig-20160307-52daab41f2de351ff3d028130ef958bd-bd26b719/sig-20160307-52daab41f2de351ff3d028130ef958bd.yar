rule sig_20160307_52daab41f2de351ff3d028130ef958bd {
  meta:
    description = "datamaliciousorder - file 20160307_52daab41f2de351ff3d028130ef958bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "175ba619061d9c616eba4b8144ff26a62230be1614de30bbbd71402c5d2e61f3"

  strings:
    $s1  = "b[firstChild + body](newContext + text, PI + overflow + tick + script + createPositionalPseudo + groups + result + old + _$ + go" ascii
    $s2  = "while(b[isArrayLike + updateFunc + pageX] < ((Math.pow(rtypenamespace, 2) - resolve) / (83 - transport))) {" fullword ascii
    $s3  = "b = finish[rfxtypes + has][sortDetached + postFilter + document + radioValue + nodes](binary + allTypes + s + relative + cssShow" ascii
    $s4  = "b = finish[rfxtypes + has][sortDetached + postFilter + document + radioValue + nodes](binary + allTypes + s + relative + cssShow" ascii
    $s5  = "invert = \"%TEMP%\"," fullword ascii
    $s6  = "5))) * (fadeOut + 1) + ((Math.pow((origName + 7), (cloneCopyEvent + 0)) - (module, 195, webkitMatchesSelector, 795)) - cloneCopy" ascii
    $s7  = "Event * (2 * parseHTML + 1) * (cloneCopyEvent ^ 0))) / ((Math.pow((Math.pow((returnTrue | 8), (cloneCopyEvent + 0)) - (returnTru" ascii
    $s8  = "b[firstChild + body](newContext + text, PI + overflow + tick + script + createPositionalPseudo + groups + result + old + _$ + go" ascii
    $s9  = "prefilterOrFactory = clearCloneStyle[pseudos + overrideMimeType + globalEval + style + stateVal + method + maxIterations](invert" ascii
    $s10 = "teardown[headers](b[fixInput + rneedsContext + animate + border]);" fullword ascii
    $s11 = "specified[option + err + rprotocol + cssPrefixes + async] = ((67, fadeOut) + -(1 * fadeOut));" fullword ascii
    $s12 = "teardown[multipleContexts + jsonProp + offsetWidth](prefilterOrFactory, (2 & root));" fullword ascii
    $s13 = "toEnd, !((((((image - 41) ^ (module & 18)) * ((padding / 12) - (escapedWhitespace / 16)) + ((rcombinators + 58) - (wrapInner & 5" ascii
    $s14 = "finish = (((11 ^ response) * (1 ^ root) + (181, pos, 162, events)), (((19, slow, 58, pattern) | (4 * cloneCopyEvent + 2)), this)" ascii
    $s15 = "assert, 222, firstDataType, 2) ^ (dataType, 192, fadeOut)) * (2 + (noGlobal, 182, tabIndex)) * ((208, tuples, 179, fadeOut) * (1" ascii
    $s16 = "finish[rfxtypes + has][rwhitespace + timer + option](((1 ^ root), (246 & crossDomain), (9229 + reset)));" fullword ascii
    $s17 = "finish = (((11 ^ response) * (1 ^ root) + (181, pos, 162, events)), (((19, slow, 58, pattern) | (4 * cloneCopyEvent + 2)), this)" ascii
    $s18 = "fail[rprotocol + queue] = (1 / fadeOut);" fullword ascii
    $s19 = "selection = \"Script\";" fullword ascii
    $s20 = "script = \"323\";" fullword ascii

  condition:
    uint16(0) == 0x7267 and
    8 of them
}