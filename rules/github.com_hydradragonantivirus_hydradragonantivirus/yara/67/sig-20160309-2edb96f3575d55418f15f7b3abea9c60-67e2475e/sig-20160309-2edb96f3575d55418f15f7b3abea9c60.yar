rule sig_20160309_2edb96f3575d55418f15f7b3abea9c60 {
  meta:
    description = "datamaliciousorder - file 20160309_2edb96f3575d55418f15f7b3abea9c60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6e923250512ec4a1220c6d970e149c3ff9c8e5d64a6614011a6f836fe3225a5"

  strings:
    $x1  = "keepScripts[manipulationTarget + preferredDoc](timeStamp + overrideMimeType, easing + tabIndex + a + manipulationTarget + status" ascii
    $s2  = "keepScripts[manipulationTarget + preferredDoc](timeStamp + overrideMimeType, easing + tabIndex + a + manipulationTarget + status" ascii
    $s3  = " + isXML + cssNumber + startTime, !(((((Math.pow(getElementsByTagName, 2) - (copyIsArray & 45)) & ((inspect ^ 607) / (access + 1" ascii
    $s4  = "attrHooks[start + dataType][finalValue + targets](((returnFalse + 5043) & (prop ^ 14951)));" fullword ascii
    $s5  = "returnValue = noGlobal[delegateTarget + jsonp + eased + defer + matchedCount + cloneCopyEvent](setDocument + elementMatchers + c" ascii
    $s6  = "container[mouseHooks + rscriptType] = ((cssPrefixes - 45) | (preexisting, 1));" fullword ascii
    $s7  = "keepScripts = attrHooks[start + dataType][cache + fadeOut + matchExpr + matchesSelector](stateString + postSelector + register +" ascii
    $s8  = "attrHooks = (((20 | maxIterations) - (80, childNodes, 87, letter)), ((Math.pow(16, testContext) - 239), this));" fullword ascii
    $s9  = "keepScripts = attrHooks[start + dataType][cache + fadeOut + matchExpr + matchesSelector](stateString + postSelector + register +" ascii
    $s10 = "returnValue = noGlobal[delegateTarget + jsonp + eased + defer + matchedCount + cloneCopyEvent](setDocument + elementMatchers + c" ascii
    $s11 = "postMap = attrHooks[start + dataType];" fullword ascii
    $s12 = "removeProp[doneName + apply](returnValue, (2 & (offset - 29)));" fullword ascii
    $s13 = "removeProp = attrHooks[start + delegate + setAttribute][cache + bindType + j + setAttribute](rclass + postFilter + then + clearC" ascii
    $s14 = "removeProp = attrHooks[start + delegate + setAttribute][cache + bindType + j + setAttribute](rclass + postFilter + then + clearC" ascii
    $s15 = "1))) & (((value, 69, optDisabled) - (4228 / createElement)), (47 * removeAttribute / (3 | cssPrefixes)))) | ((((4 - attributes) " ascii
    $s16 = "removeProp[status + createOptions + nextSibling](Expr);" fullword ascii
    $s17 = "always = iframe;" fullword ascii
    $s18 = "container = removeProp;" fullword ascii
    $s19 = "var apply = \"oFile\"," fullword ascii
    $s20 = "var Symbol = \"r\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}