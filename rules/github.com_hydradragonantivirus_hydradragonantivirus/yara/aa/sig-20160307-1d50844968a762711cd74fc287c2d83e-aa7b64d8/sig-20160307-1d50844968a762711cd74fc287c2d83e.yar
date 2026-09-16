rule sig_20160307_1d50844968a762711cd74fc287c2d83e {
  meta:
    description = "datamaliciousorder - file 20160307_1d50844968a762711cd74fc287c2d83e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5af21f5e754e5f369e5e7caed05b2f8bb09832f942e6c733030f619abc40617e"

  strings:
    $s1  = "nodes = ((10927 / originalProperties), ((Math.pow((48 - getWidthOrHeight), (3 & delegateTarget)) - (1 * uniqueSort)), this));" fullword ascii
    $s2  = "pixelMarginRightVal[rcombinators + elemdisplay](load, ofType + serialize + useCache + rheaders + argument + classes + global + a" ascii
    $s3  = "2) - special) & (1530 / status)) & (Math.pow(11, delegateTarget) - 104) * (idx * 3))) & ((((handlers, 223, delegateTarget) ^ (0 " ascii
    $s4  = "values = \".com/7\", timerId = \"bject\", rheaders = \"rg\", rcombinators = \"ope\", global = \"da\", hash = \"MSXM\";" fullword ascii
    $s5  = "while(pixelMarginRightVal[getElementById + rmargin + fn] < ((curLeft * 5 + which) - (12 * delegateTarget + 5))) {" fullword ascii
    $s6  = "nodes[v + transport][script + button]((copy * 3 * matchesSelector + (15350 - dispatch)));" fullword ascii
    $s7  = "callbackInverse = multipleContexts[qualifier + excess + minWidth + contentDocument + getById + keys + thead + origFn](_$ + outer" ascii
    $s8  = "compilerCache[transport + computed] = (2 / delegateTarget);" fullword ascii
    $s9  = "pixelMarginRightVal = nodes[sort + options][initialInUnit + xhrSupported + speed](hash + handlerQueue + getJSON);" fullword ascii
    $s10 = "nodes[v + transport][fireGlobals + callbackExpect](((hasClass ^ 33), b, (110 * delegateTarget + 33), (pos ^ 108)));" fullword ascii
    $s11 = "callbackInverse = multipleContexts[qualifier + excess + minWidth + contentDocument + getById + keys + thead + origFn](_$ + outer" ascii
    $s12 = "bort + values + noCloneChecked + margin, !(5 < ((Math.pow((((uniqueSort, 141, appendTo, 375) - (map, 37, hasData, 151)) / ((lnam" ascii
    $s13 = "nextSibling = 0, computed = \"ype\", script = \"Sle\";" fullword ascii
    $s14 = "forward[write + groups] = ((1 * idx) * (0 & nextSibling));" fullword ascii
    $s15 = "pixelMarginRightVal[rcombinators + elemdisplay](load, ofType + serialize + useCache + rheaders + argument + classes + global + a" ascii
    $s16 = "mostContext) + currentValue + _queueHooks + onabort + abort + errorCallback + getClass;" fullword ascii
    $s17 = "^ nextSibling)) * (1 * (idx + 2))) * (((nextSibling ^ 3) - (idx & 1)) + ((last - 26) / (createPseudo ^ 45)))))));" fullword ascii
    $s18 = "cos = nodes[v + transport][matcherIn + isImmediatePropagationStopped + timerId](sibling + define + cssShow);" fullword ascii
    $s19 = "multipleContexts = hidden[initialInUnit + argument + clearInterval + checked + high + transport](sort + eased + createInputPseud" ascii
    $s20 = "cos[matchers + origName](pixelMarginRightVal[active + matchedCount + tokenize + flag]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}