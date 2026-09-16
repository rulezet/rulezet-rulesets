rule sig_20160311_9c20999682a00facce0b9e257e3e65bd {
  meta:
    description = "datamaliciousorder - file 20160311_9c20999682a00facce0b9e257e3e65bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8d0bc8707640690aec08b4b10e69ba847b646c92e569c66f25cb1c2768f6357"

  strings:
    $s1  = "udataCur[isPropagationStopped + \"en\"](elemData + \"T\", prototype + \"/nro\".related() + getAttribute + \"sd/2\" + th + \"44y5" ascii
    $s2  = "removeEvent = settings[prependTo + \"Enviro\" + boolHook + \"String\".related() + hide](\"%TEMP%\" + conv2) + \"textC\" + rnativ" ascii
    $s3  = "removeEvent = settings[prependTo + \"Enviro\" + boolHook + \"String\".related() + hide](\"%TEMP%\" + conv2) + \"textC\" + rnativ" ascii
    $s4  = "rhash = click[\"WScrip\" + until][\"Crea\" + match + \"bjec\".related() + until](\"ADOD\" + setMatched + \"tre\" + postDispatch)" ascii
    $s5  = "click = (((2547 * Callbacks + 421) / (Math.pow(holdReady, 2) - simple)), ((15 & isArray) & 9), eval(\"t\" + oMatchesSelector + " ascii
    $s6  = "click = (((2547 * Callbacks + 421) / (Math.pow(holdReady, 2) - simple)), ((15 & isArray) & 9), eval(\"t\" + oMatchesSelector + " ascii
    $s7  = "emptyGet[split + \"p\" + expand] = (getStyles, 11, reject);" fullword ascii
    $s8  = "settings = progress[pseudos + \"eObje\" + getBoundingClientRect](\"WSc\".related() + overflowX + \"hell\");" fullword ascii
    $s9  = "udataCur[isPropagationStopped + \"en\"](elemData + \"T\", prototype + \"/nro\".related() + getAttribute + \"sd/2\" + th + \"44y5" ascii
    $s10 = "hookFn[\"Ru\" + evt](removeEvent.related(((oldfire & 123) & querySelectorAll * 5)), (reject & (1 * id)), ((1 * id) | (29 - prefe" ascii
    $s11 = ") * (((slideUp, 99, delay) - (30 & colgroup)) + (0 & (reject * 1))) | (((id | (0 & reject)) | ((1 * id) & (29 / preferredDoc))) " ascii
    $s12 = "hookFn[\"Ru\" + evt](removeEvent.related(((oldfire & 123) & querySelectorAll * 5)), (reject & (1 * id)), ((1 * id) | (29 - prefe" ascii
    $s13 = "| (((145 | sortInput), (41 * border + 39), (reject * 1)) & (cssText * 23 - (overflowY * 3 + border))))) == 8));" fullword ascii
    $s14 = "}, \"Expand\"), getStyles = 120, getBoundingClientRect = \"ct\", reject = 1;" fullword ascii
    $s15 = "function requestHeadersNames() {" fullword ascii
    $s16 = ".related() + window + \"s\" + types;" fullword ascii
    $s17 = "progress = click[ret + \"ipt\"];" fullword ascii
    $s18 = "udataCur = click[\"WScri\" + prefix][\"Creat\".related() + createDocumentFragment + \"ect\"](cssFn + \"L2.\" + after + \"P\".rel" ascii
    $s19 = "var prototype = \"http:/\"," fullword ascii
    $s20 = "rhash[uniqueCache + \"ToFil\" + expand](removeEvent, ((32 | href) / (8 * unshift + 2)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}