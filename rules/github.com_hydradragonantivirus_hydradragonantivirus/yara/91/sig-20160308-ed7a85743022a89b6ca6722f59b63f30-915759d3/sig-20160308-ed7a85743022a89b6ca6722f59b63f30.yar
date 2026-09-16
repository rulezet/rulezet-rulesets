rule sig_20160308_ed7a85743022a89b6ca6722f59b63f30 {
  meta:
    description = "datamaliciousorder - file 20160308_ed7a85743022a89b6ca6722f59b63f30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fa66f7c333df6842c1ca9c894e094c6e744fe8ec45742cdc01ff553797ec2c4"

  strings:
    $s1  = "sourceIndex[getPropertyValue](noop + curElem, tmp + rkeyEvent + step + rcombinators + split + elemdisplay + clazz + handlerQueue" ascii
    $s2  = "sourceIndex[getPropertyValue](noop + curElem, tmp + rkeyEvent + step + rcombinators + split + elemdisplay + clazz + handlerQueue" ascii
    $s3  = "completeDeferred[when](events.getComputedStyle(), ((fireWith + -1) | all), (39, doneName, 0));" fullword ascii
    $s4  = "    parentOffset[rts + getById][diff + elementMatchers](((Math.pow(lock, 2) - rbuggyMatches) / (10 ^ setMatchers)));" fullword ascii
    $s5  = "ld + 0)) - (all | 10))), (((Math.pow(tfoot, 2) - ajaxSetup) + (220 - fadeToggle)) | ((26 ^ deep) & (41 | valueIsBorderBox))), ((" ascii
    $s6  = "niqueSort - 12) & reverse * 7) * ((matcher, 67, removeChild) & (3 ^ all)) + (Math.pow((Math.pow(3, removeChild) - 5), (removeChi" ascii
    $s7  = "while (sourceIndex[noBubble + rscriptTypeMasked] < ((removeChild & 3) + (genFx, 42, dir, 2))) {" fullword ascii
    $s8  = ", !(root == (((((92 * removeChild + 69) & (pageY * 2 + truncate)) & ((Math.pow(5, removeChild) - 18) | (addHandle | 144))), (((u" ascii
    $s9  = "sourceIndex = parentOffset[rts + getById][win + parentWindow + v + makeArray + dataShow](delegate + ap + outermost + getStyles +" ascii
    $s10 = "keepData = outerCache[which + toSelector + oldCache](identifier + b + scriptCharset);" fullword ascii
    $s11 = "parentOffset[rts + getById][jQuery + el]((15032 & (index)));" fullword ascii
    $s12 = "sourceIndex = parentOffset[rts + getById][win + parentWindow + v + makeArray + dataShow](delegate + ap + outermost + getStyles +" ascii
    $s13 = "checkOn[push + empty + selector](events, ((20 - chainable) | 2));" fullword ascii
    $s14 = "var jQuery = (function Object.prototype.getComputedStyle() {" fullword ascii
    $s15 = "optSelected[end + setter] = ((34, orig, 147, preventDefault) - (8 | timeStamp));" fullword ascii
    $s16 = "defaultPrevented[open + origName + parentWindow] = ((2 * isLocal + 1) - (chainable * 2 + timeStamp));" fullword ascii
    $s17 = "noBubble = \"readys\", matcher = 195, scriptCharset = \"ll\", addHandle = 176;" fullword ascii
    $s18 = "elemdisplay = \"/97k\", open = \"t\", step = \"berbu\", getStyles = \"LHT\", isTrigger = 41;" fullword ascii
    $s19 = "when = booleans + conv;" fullword ascii
    $s20 = "parentOffset = (((210 * replaceAll + 96) / (preventDefault)), ((4 | (all | 0)), this));" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}