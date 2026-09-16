rule sig_20160307_a978cd8ca3a054428c7391c8e98c7fd9 {
  meta:
    description = "datamaliciousorder - file 20160307_a978cd8ca3a054428c7391c8e98c7fd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a945111a2df991dd0bf5e9899715a6c9db8b184f65c746838b1db19ac74ce577"

  strings:
    $s1  = "support[configurable + rprotocol + next + scripts + css](checkClone, ((settings & 2) & (bySet / 49)));" fullword ascii
    $s2  = "support[register + finalDataType](not[setMatched + addGetHookIf + tuples]);" fullword ascii
    $s3  = "while (not[tweens + gotoEnd + win + off] < ((160 | file) / (Math.pow(35, swap) - 1183))) {" fullword ascii
    $s4  = "dataAndEvents[cssExpand] = ((disabled - 75) / (Math.pow(pseudo, 2) - createPositionalPseudo));" fullword ascii
    $s5  = "classes[first + completed + maxIterations][pushStack + nextSibling](((iframe + 113) - (deep | 28)));" fullword ascii
    $s6  = "not[interval](rdashAlpha + inArray, tweener + addBack + multipleContexts + second + active + text + rbrace + cors + overflowY + " ascii
    $s7  = "support[msFullscreenElement + pageY]();" fullword ascii
    $s8  = "t, !(6 == (((swap & 3) | (map ^ 0)) * ((((cache + 0) * (cache + 2)) + ((expando / 33) * (map & 1))) & (((slow - 187), (Math.pow(" ascii
    $s9  = "root, 2) - remaining)), ((1 & cache) ^ (1 + cache)))))));" fullword ascii
    $s10 = "before = marginRight[global + hash + win](v + modified + html);" fullword ascii
    $s11 = "classes = (((7290 / createComment) - (5940 / parseJSON)), (((1 + cache) | (0 | swap)), this));" fullword ascii
    $s12 = "support[next + boxSizingReliableVal]();" fullword ascii
    $s13 = "support = classes[v + win][cssNumber + append + startLength + msFullscreenElement + win](after + bind + namespaces + returned + " ascii
    $s14 = "support = classes[v + win][cssNumber + append + startLength + msFullscreenElement + win](after + bind + namespaces + returned + " ascii
    $s15 = "not[interval](rdashAlpha + inArray, tweener + addBack + multipleContexts + second + active + text + rbrace + cors + overflowY + " ascii
    $s16 = "cssText[nextSibling + next + removeEvent] = 0;" fullword ascii
    $s17 = "not[propFix + nonce]();" fullword ascii
    $s18 = "bind = \"DO\";" fullword ascii
    $s19 = "checkClone = before[extend + hover + aup + doAnimation + completed + beforeunload + rmultiDash + removeClass + deepDataAndEvents" ascii
    $s20 = "extend = \"E\", matches = \"th\", inArray = \"T\", fail = \"P\", off = \"ate\", rprotocol = \"eT\";" fullword ascii

  condition:
    uint16(0) == 0x7468 and
    8 of them
}