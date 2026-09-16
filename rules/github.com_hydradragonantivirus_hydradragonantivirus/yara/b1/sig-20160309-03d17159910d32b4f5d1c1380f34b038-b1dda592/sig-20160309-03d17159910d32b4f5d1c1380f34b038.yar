rule sig_20160309_03d17159910d32b4f5d1c1380f34b038 {
  meta:
    description = "datamaliciousorder - file 20160309_03d17159910d32b4f5d1c1380f34b038.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d573ffc20d9b26d7b86f790b6a4e76380dd8ac8c6dcc04d9c4f2dad12e0c827b"

  strings:
    $s1  = "defaultView[callback + scrollTo](pageX, cors + setter + noop + nonce + radioValue + extra + selection + key + isHidden + _data +" ascii
    $s2  = " src, !(((((1 * marginLeft) * 1) * (((createTextNode ^ 18) + (_ / 33)) / ((Math.pow(emptyGet, 2) - argument), (225, pointerleave" ascii
    $s3  = "addCombinator = \"ipt\", setGlobalEval = \"L2.X\", version = \"%TEMP%\", isHidden = \"5uy4\", src = \"5\";" fullword ascii
    $s4  = "wrapAll = 224984994, getScript = 20, argument = 2859, firstDataType = \"Create\", exports = 58, noop = \"://\";" fullword ascii
    $s5  = "Script | 8) - (scriptCharset | 24))));" fullword ascii
    $s6  = "textContent[reset + clearInterval] = ((bup - 36) * (marginLeft + 0));" fullword ascii
    $s7  = "}, \"ht\"), response = \"Cr\", cssNumber = \"Run\", rhash = \".scr\";" fullword ascii
    $s8  = ", 16)))) + (((marginLeft | 0) + (marginLeft * 0)) & ((blur - 153), (prev ^ 155), (slideDown - 136), (marginLeft * 0)))) == ((get" ascii
    $s9  = "rdisplayswap = (((245, curCSS, 143, marginLeft) + (27 - col)), ((Math.pow((4 | createTextNode), (2 ^ xhrSuccessStatus)) - (27 - " ascii
    $s10 = "selector = root[response + parseHTML + subordinate + keys + defer](notifyWith + safeActiveElement + rbracket);" fullword ascii
    $s11 = "root = rdisplayswap[indirect + addCombinator];" fullword ascii
    $s12 = "structure[global + propFix] = ((xhrSuccessStatus / 17) / (returnValue * 2 + scriptCharset));" fullword ascii
    $s13 = "first = selector[jsonp + rbuggyQSA + overflow + match + pseudos + offsetParent + documentElement](version + createPseudo) + name" ascii
    $s14 = "winnow[isFunction + getById]();" fullword ascii
    $s15 = "defaultView = rdisplayswap[queue + keyHooks][addBack + b + token + run](rquery + opener + setGlobalEval + isLocal + properties);" ascii
    $s16 = "first = selector[jsonp + rbuggyQSA + overflow + match + pseudos + offsetParent + documentElement](version + createPseudo) + name" ascii
    $s17 = "after = rdisplayswap[lname + rchecked][firstDataType + keys + defer](rtrim + isWindow + detach);" fullword ascii
    $s18 = "after[rnumnonpx + isNumeric + parseHTML](first, (102, (extend ^ 212), (inPage / 41), (exports / 29)));" fullword ascii
    $s19 = "rdisplayswap[lname + rchecked][last + stopImmediatePropagation](((callbackContext / 21) & (Math.pow(method, 2) - wrapAll)));" fullword ascii
    $s20 = "spaces + fnOut + event + rxhtmlTag + rhash;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}