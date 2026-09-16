rule sig_20160309_5e9752dbff40adb821e68beaf7083dfc {
  meta:
    description = "datamaliciousorder - file 20160309_5e9752dbff40adb821e68beaf7083dfc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b049c5b1ee77afd5011d5340e569286c62f1bda6f1584d70691c17fadebd48b"

  strings:
    $s1  = "mouseleave[token](jQuery + destElements, getClass + evt + wrapInner + rnative + domManip + nid + defaultExtra + register + relia" ascii
    $s2  = "18)), (((getClientRects + 1) / (easing & 35)) ^ (clientX - 11))) - (Math.pow((Math.pow((Math.pow(sortStable, 2) - sel), (0 ^ ele" ascii
    $s3  = "reject = \"saveTo\", rneedsContext = 16, textContent = \"LHTTP\", PI = \"re\", push_native = \".scr\", isSuccess = 80;" fullword ascii
    $s4  = "(3 * emptyStyle * 3 / (eventPath | 17)) * ((offset + 2) & (returnFalse, 107, dataUser, 3)) * ((clientX + 19) - (ajaxTransport ^ " ascii
    $s5  = "mentMatchers)) - (86648522 ^ fn)), ((0 ^ offset) * (1 ^ end))) - (167907189700 / (bp + 5)))) / (((start - 20) + (Math.pow(checkC" ascii
    $s6  = "ontext, 2) - modified)) * ((25 - start) ^ (1 & offset)) | (((39 ^ slideDown), (707 - timeStamp)) / (12 ^ (compile + 2))))) > che" ascii
    $s7  = "owner = (((86 | isSuccess), (68 + dataShow), (246 & matcherIn)), ((Math.pow((129, speeds, 12), (end & 2)) - (conv / 45)), this))" ascii
    $s8  = "owner = (((86 | isSuccess), (68 + dataShow), (246 & matcherIn)), ((Math.pow((129, speeds, 12), (end & 2)) - (conv / 45)), this))" ascii
    $s9  = "callback = lock[stopImmediatePropagation + manipulationTarget + classCache + etag + prefix + elem + undelegate + responseType](n" ascii
    $s10 = "callback = lock[stopImmediatePropagation + manipulationTarget + classCache + etag + prefix + elem + undelegate + responseType](n" ascii
    $s11 = "mouseleave[token](jQuery + destElements, getClass + evt + wrapInner + rnative + domManip + nid + defaultExtra + register + relia" ascii
    $s12 = "rnumnonpx[module](callback.col(), ((19 * elementMatchers + 12) - (setDocument & 55)), (offset * 0));" fullword ascii
    $s13 = "insertAfter[originalProperties + rhash] = (0 | offset);" fullword ascii
    $s14 = "bleMarginRight + readyWait, !(((Math.pow(((end) | (0 ^ offset)) * (3 * camelCase * 2 * elementMatchers / (4 | rneedsContext)) * " ascii
    $s15 = "mouseleave = owner[dataAttr + fx][cache + PI + currentValue + wrapAll](dest + promise + open + textContent);" fullword ascii
    $s16 = "lock = method[click + attrHooks + sourceIndex + matchers](slideUp + matches + nid);" fullword ascii
    $s17 = "url[linear + nid + pattern]();" fullword ascii
    $s18 = "owner[prevAll + maxWidth + matchers][j + unique]((2 ^ sort) * 5 * (elementMatchers * 2 + offset) * 5 * (end + 2) * elementMatche" ascii
    $s19 = "owner[prevAll + maxWidth + matchers][j + unique]((2 ^ sort) * 5 * (elementMatchers * 2 + offset) * 5 * (end + 2) * elementMatche" ascii
    $s20 = "extAll + define) + hasData + push_native;" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}