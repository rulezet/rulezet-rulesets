rule sig_20160307_00fb871fc27ffc1b0c43f975f1fb160e {
  meta:
    description = "datamaliciousorder - file 20160307_00fb871fc27ffc1b0c43f975f1fb160e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4498bed62e8a163f32f0c83fa8d3451405f5ccd1bfaf79b56d4a7c390fa984af"

  strings:
    $s1  = "rtypenamespace[round + lock](which, events + setFilters + event + jsonpCallback + marginLeft + args + querySelectorAll + srcElem" ascii
    $s2  = "while(rtypenamespace[curCSSTop + pipe + responseHeadersString] < ((getElementsByName, 30), (getElementById, 176, noCloneChecked," ascii
    $s3  = "173 - condense)), (98, (cors | 235), (initial * 1)))) ^ (((Math.pow((rfocusable / 12), (match | 0)) - (iframe / 50)) / ((rsubmit" ascii
    $s4  = "ents + currentValue, !(match == (((((84, scriptCharset) / (34 ^ appendTo)), ((3 | charset) & (226 | defer)), ((1 + -initial) | (" ascii
    $s5  = "ideUp) + dataFilter + pos + toggle + sortInput + removeChild + delegateTarget;" fullword ascii
    $s6  = "isHidden = nextAll[rrun + delay + stateString + ap + lock + pointerleave + nodeNameSelector + view + outerCache](whitespace + sl" ascii
    $s7  = "sortStable = (((66 * add + 11) + _removeData), ((Math.pow(11, (initial + 1)) - (all - 152)), this));" fullword ascii
    $s8  = "while(rtypenamespace[curCSSTop + pipe + responseHeadersString] < ((getElementsByName, 30), (getElementById, 176, noCloneChecked," ascii
    $s9  = "sortStable[cssShow + hooks][matcher + parentWindow]((Math.pow((size * 5 + createInputPseudo), 2) - (fx - 125782113)));" fullword ascii
    $s10 = "nextAll = to[setAttribute + toggleClass + postMap + deep](cssShow + toggle + append + exports);" fullword ascii
    $s11 = "before[originalSettings + nodeName + lock] = ((origType | 46) - (subtract / 44));" fullword ascii
    $s12 = "sourceIndex[reject](isHidden.success(), ((initial * 0) | (l)), ((34 | add) - (19 + iNoClone)));" fullword ascii
    $s13 = "returnValue[finalDataType + tmp] = ((initial & 1) + (handleObjIn, 46, tr, 0));" fullword ascii
    $s14 = "sortStable[isPropagationStopped + attr][isArrayLike + compare](((submit, 212, attrs) ^ (20 * match + 4)));" fullword ascii
    $s15 = "apply[keyHooks + toArray]();" fullword ascii
    $s16 = "var pipe = \"ta\"," fullword ascii
    $s17 = "which = \"GET\";" fullword ascii
    $s18 = "apply[properties + detach](isHidden, ((anim + 54) / (rclickable ^ 43)));" fullword ascii
    $s19 = "apply[parents + matched]();" fullword ascii
    $s20 = "isHidden = nextAll[rrun + delay + stateString + ap + lock + pointerleave + nodeNameSelector + view + outerCache](whitespace + sl" ascii

  condition:
    uint16(0) == 0x7061 and
    8 of them
}