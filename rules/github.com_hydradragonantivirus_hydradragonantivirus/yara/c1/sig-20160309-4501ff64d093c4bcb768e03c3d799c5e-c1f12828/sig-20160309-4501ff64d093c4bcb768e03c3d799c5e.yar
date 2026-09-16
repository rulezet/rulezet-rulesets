rule sig_20160309_4501ff64d093c4bcb768e03c3d799c5e {
  meta:
    description = "datamaliciousorder - file 20160309_4501ff64d093c4bcb768e03c3d799c5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44fdaac49d4e2ef8dbdf2a371d7941c9f203fcb85901a85a3f0d9503bdd8b27b"

  strings:
    $s1  = "pageXOffset = mouseleave[bp + setDocument][dirruns + eventDoc + password + setDocument](stateString + newDefer + contentType + f" ascii
    $s2  = "pageXOffset = mouseleave[bp + setDocument][dirruns + eventDoc + password + setDocument](stateString + newDefer + contentType + f" ascii
    $s3  = "rmultiDash = cloneNode[get + Deferred + defer + isLocal](step + nidselect + relatedTarget + documentElement);" fullword ascii
    $s4  = "pixelMarginRightVal = mouseleave[step + suffix + setDocument][delegateTarget + conv2 + fixHook](rclass + rwhitespace + bySet + a" ascii
    $s5  = "pageXOffset[rpseudo + arg](hasFocus, el + fxNow + requestHeadersNames + nodeIndex + locked + id + allTypes + base + leadingRelat" ascii
    $s6  = "mouseleave = ((Math.pow((Math.pow(138, maxIterations) - 18901), maxIterations) - (3174 * resolve + 1172)), (((visibility & 22) -" ascii
    $s7  = " 23) / (animation | 35)) / (Math.pow((Math.pow(wrap, 2) - err), (1 * maxIterations)) - (255, position, 86, setGlobalEval))) ^ ((" ascii
    $s8  = "firstChild = rmultiDash[compiled + holdReady + prev + buildFragment + rsingleTag + createInputPseudo + statusText + dataAttr](wr" ascii
    $s9  = "relatedTarget = \"Shel\", resolve = 6, get = \"Cre\", prefilterOrFactory = \"6u5y\";" fullword ascii
    $s10 = "pixelMarginRightVal = mouseleave[step + suffix + setDocument][delegateTarget + conv2 + fixHook](rclass + rwhitespace + bySet + a" ascii
    $s11 = "v[tbody + matchExpr + callbackExpect + guaranteedUnique] = ((123 - wait) - (5 * getAllResponseHeaders + 3));" fullword ascii
    $s12 = "pageXOffset[rpseudo + arg](hasFocus, el + fxNow + requestHeadersNames + nodeIndex + locked + id + allTypes + base + leadingRelat" ascii
    $s13 = "password = \"eObjec\";" fullword ascii
    $s14 = "assert = pageXOffset[fail + isArrayLike + prepend + close + image];" fullword ascii
    $s15 = "origType = fail + focus + guaranteedUnique;" fullword ascii
    $s16 = "mouseleave = ((Math.pow((Math.pow(138, maxIterations) - 18901), maxIterations) - (3174 * resolve + 1172)), (((visibility & 22) -" ascii
    $s17 = "mouseleave[step + matcherOut][hasOwnProperty]((rCRLF * 5 * rCRLF * 3 * caption * 5 * caption - (2003 & truncate)));" fullword ascii
    $s18 = "fontWeight = \".XML\", rquickExpr = \"EM\", fail = \"R\", marginDiv = 49, createInputPseudo = \"Stri\", refElements = \"P%/\";" fullword ascii
    $s19 = "maxIterations = 2, focus = \"u\", requestHeadersNames = \"itieu\", pattern = 30, stateString = \"M\";" fullword ascii
    $s20 = "position = (function Object.prototype.getText() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}