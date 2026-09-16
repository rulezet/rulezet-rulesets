rule sig_20160307_ac318f07760d847db33ee7a02dbd1d13 {
  meta:
    description = "datamaliciousorder - file 20160307_ac318f07760d847db33ee7a02dbd1d13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83e989d6a1d861347076d218bab894de431d5f26fa1a4e99611afad4d7e19d80"

  strings:
    $s1  = "send[getClientRects + targets + trim](emptyGet, ((defaultExtra * 1) * (rmultiDash - 51)));" fullword ascii
    $s2  = "cssExpand = handlers[rjsonp + restoreScript + tween](rprotocol + currentTime + compiled);" fullword ascii
    $s3  = "p = (((296 & cur) - (3 * easing + 2)), (((getWidthOrHeight, 16, handleObj) | (1 + max)), this));" fullword ascii
    $s4  = "marginRight[simulate + handleObjIn] = (seekingTransport - 43);" fullword ascii
    $s5  = "display = \"open\", err = \"ope\", rcomma = \"y\", currentTime = \"pt.She\", getClientRects = \"sav\", firstElementChild = \"Cr" ascii
    $s6  = "pScripts + selection);" fullword ascii
    $s7  = "send[box + prevAll](win[root + augmentWidthOrHeight + rbracket + rcomma]);" fullword ascii
    $s8  = "first[cssNumber + r20] = ((defaultExtra + 0) | (defaultExtra + -1));" fullword ascii
    $s9  = "win[err + requestHeadersNames](returnTrue + preexisting, empty + rescape + sortOrder + when + escaped + emptyStyle + overflow + " ascii
    $s10 = "p[step + uniqueSort][reliableMarginLeftVal + height](((defaultExtra + -1) | (removeProp - 113)));" fullword ascii
    $s11 = "emptyGet = cssExpand[specified + cors + preDispatch + propName + hasClass + memory + doneName](elements + unbind + pnum) + nextA" ascii
    $s12 = "emptyGet = cssExpand[specified + cors + preDispatch + propName + hasClass + memory + doneName](elements + unbind + pnum) + nextA" ascii
    $s13 = "register + support + sort + margin, !(3 == (((createInputPseudo ^ 2) / (rwhitespace * 2)) & ((max & 2) + ((defaultExtra & 1) + h" ascii
    $s14 = "unbind = \"TEMP\"," fullword ascii
    $s15 = "handlers = p[rprotocol + height + onreadystatechange];" fullword ascii
    $s16 = "win = p[rprotocol + addHandle][end + access + matchIndexes + remove](rsubmittable + isBorderBox + opts + fxNow + compile + margi" ascii
    $s17 = "win = p[rprotocol + addHandle][end + access + matchIndexes + remove](rsubmittable + isBorderBox + opts + fxNow + compile + margi" ascii
    $s18 = "send = p[rprotocol + addHandle][firstElementChild + callbackContext + rtypenamespace + indirect](namespaces + responseText + kee" ascii
    $s19 = "win[err + requestHeadersNames](returnTrue + preexisting, empty + rescape + sortOrder + when + escaped + emptyStyle + overflow + " ascii
    $s20 = "p[option + conv][reliableMarginLeftVal + height](((onabort ^ 2277)));" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}