rule sig_20160308_4e14e1bf4f60d4f1ac5e66fc04d844d9 {
  meta:
    description = "datamaliciousorder - file 20160308_4e14e1bf4f60d4f1ac5e66fc04d844d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b8badd38d500f900166e35b3331eb80774db9bd09e49bb7f7680abc58a8813f"

  strings:
    $s1  = "dataPriv = slideToggle[pushStack + noop + errorCallback + current + responseText + node + forward](scripts + prevObject + respon" ascii
    $s2  = "scrollTo[transport + inspected](pixelMarginRightVal + msg, parentNode + self + eventHandle + firstElementChild + isHidden + coll" ascii
    $s3  = "textContent[base](dataPriv.headers(), ((xhrSupported * 0) & xhrSupported), ((1 * xhrSupported) + -(1 | curTop)));" fullword ascii
    $s4  = ", xhrSupported) * (3 & hooks))) == (((((11 + radioValue) ^ (18 * tokens + 17)) - ((timerId ^ 37) & (values - 47))) + (((root - 3" ascii
    $s5  = "seHeadersString + handler) + count + qsaError + delegateTarget + attrId;" fullword ascii
    $s6  = "isArray[dirrunsUnique + dataAttr + exports + realStringObj] = ((removeChild * 3 + prototype) - (Math.pow(48, copy) - 2254));" fullword ascii
    $s7  = "while (scrollTo[cos + bindType + toArray] < ((45 + then) / (Math.pow(17, copy) - 268))) {" fullword ascii
    $s8  = "4) ^ xhrSupported) * ((1 & xhrSupported) * (115 / nType)))) - ((Math.pow(((Math.pow(106, copy) - 11105), (Math.pow(matchIndexes," ascii
    $s9  = "dataPriv = slideToggle[pushStack + noop + errorCallback + current + responseText + node + forward](scripts + prevObject + respon" ascii
    $s10 = "slideToggle = clientTop[gotoEnd + head + rsingleTag + username + which](type + isWindow + setOffset);" fullword ascii
    $s11 = "    rhtml[needsContext + handleObjIn + argument + define][clearCloneStyle + readyState](((getJSON - 100) & (preferredDoc & 119))" ascii
    $s12 = "slow[url + elementMatcher + toArray](dataPriv, ((xhrSupported ^ 26) - (pattern ^ 16)));" fullword ascii
    $s13 = "    rhtml[needsContext + handleObjIn + argument + define][clearCloneStyle + readyState](((getJSON - 100) & (preferredDoc & 119))" ascii
    $s14 = "ection + keepScripts + msFullscreenElement + specified + position, !(((hooks & 3) & (((attr & 111) / (s, 125, outermostContext, " ascii
    $s15 = "transport = \"op\", selectors = \"WSc\", shift = \"Sleep\", outermostContext = 241, head = \"r\";" fullword ascii
    $s16 = " 2) - bup)), (1 * (copy + 0))) - ((responses * 4 + pageX) * (138 / nType) + (0 | rneedsContext))) | (((1 | types) | (5 ^ div)) &" ascii
    $s17 = "rhtml[needsContext + hasContent + errorCallback + define][shift](((eased | 614472) / (notify | 40)));" fullword ascii
    $s18 = "scrollTo[transport + inspected](pixelMarginRightVal + msg, parentNode + self + eventHandle + firstElementChild + isHidden + coll" ascii
    $s19 = "33)) + ((xhrSupported & 1) & (extra, 247, xhrSupported)))) * ((((140 | pageX), 2) ^ (xhrSupported + 0)) & ((resolveContexts, 117" ascii
    $s20 = "var forward = \"s\"," fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}