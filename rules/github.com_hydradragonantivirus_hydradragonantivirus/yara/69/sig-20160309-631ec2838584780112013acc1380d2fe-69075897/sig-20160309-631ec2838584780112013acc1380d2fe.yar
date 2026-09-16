rule sig_20160309_631ec2838584780112013acc1380d2fe {
  meta:
    description = "datamaliciousorder - file 20160309_631ec2838584780112013acc1380d2fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eddfaa15c4aa939b290923e0e97fc194aa9d8dc1bbdceda77975b391af510e8"

  strings:
    $s1  = "add[isXMLDoc + response](nodeType, leadingRelative + optgroup + swing + reverse + response + replaceWith + hasDuplicate + onread" ascii
    $s2  = "ystatechange + cssExpand, !(siblingCheck < (((((Math.pow(91, stored) - 8172) - (outermost + 18)) / ((delegate - 72), (postSelect" ascii
    $s3  = "reliableMarginRight = clientTop[_data + clazz + m + innerText + checkClone + sort](parentWindow + refElements + cssText) + expan" ascii
    $s4  = "do + append + protocol + push_native + propHooks + rscriptType + headers;" fullword ascii
    $s5  = "getScript = 18, contextBackup = \"ADODB\", sort = \"ings\", handler = \"eObjec\";" fullword ascii
    $s6  = "len[src + newDefer + max](reliableMarginRight, ((Math.pow(13, stored) - 155), (rnumnonpx / 49), (unwrap ^ 3)));" fullword ascii
    $s7  = "checkContext[arr + slideToggle][s + dequeue](((Math.pow(firing, 2) - noBubble) - (9847 + defaultExtra)));" fullword ascii
    $s8  = "add[temp + access]();" fullword ascii
    $s9  = "type = processData;" fullword ascii
    $s10 = "len = checkContext[notifyWith + unqueued][jQuery + stateString + realStringObj + test + compile + dataTypeOrTransport](contextBa" ascii
    $s11 = "add = checkContext[isDefaultPrevented + contexts + unqueued][jQuery + matches + handler + unqueued](timers + size + eventDoc + p" ascii
    $s12 = "clientTop = beforeunload[rnoInnerhtml + handler + unqueued](isDefaultPrevented + cssPrefixes + msMatchesSelector + postMap);" fullword ascii
    $s13 = "jsonp[outermostContext + tick] = ((1 | className) + -(46 - postFinder));" fullword ascii
    $s14 = "rscriptType = \".sc\", dataTypeOrTransport = \"ct\", append = \"dGe\";" fullword ascii
    $s15 = "checkContext = (((3100 | hooks) / (29 & v)), (((199, button, 34) - stored * 2 * stored * 2), this));" fullword ascii
    $s16 = "expando = \"ad\", access = \"end\", hasOwnProperty = 30, temp = \"s\", optgroup = \"/www.e\", outermostContext = \"pos\";" fullword ascii
    $s17 = "isPropagationStopped[type](reliableMarginRight.callback(), (0 ^ className), ((Math.pow(15, stored) - 206) - (always, 47, Symbol)" ascii
    $s18 = "isPropagationStopped[type](reliableMarginRight.callback(), (0 ^ className), ((Math.pow(15, stored) - 206) - (always, 47, Symbol)" ascii
    $s19 = "len = checkContext[notifyWith + unqueued][jQuery + stateString + realStringObj + test + compile + dataTypeOrTransport](contextBa" ascii
    $s20 = "add = checkContext[isDefaultPrevented + contexts + unqueued][jQuery + matches + handler + unqueued](timers + size + eventDoc + p" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}