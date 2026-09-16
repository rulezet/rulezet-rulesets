rule sig_20160307_65962d6d4ca7f17caa7960fca406951c {
  meta:
    description = "datamaliciousorder - file 20160307_65962d6d4ca7f17caa7960fca406951c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05461a2b47d4d16a8364b54d19d4f31cf9b795025c5f705fcc973f401980a02f"

  strings:
    $s1  = "getElementsByClassName[hasDuplicate](maxIterations + udataCur, delegateTarget + rfxtypes + rts + classNames + getText + arr + rs" ascii
    $s2  = "+ (combinator & 0)) * (((Math.pow(curElem, 2) - rdashAlpha) | (116 * clearInterval + 8)), ((tfoot - 108) - (getAttributeNode * 3" ascii
    $s3  = "getElementsByClassName = fadeOut[disableScript + n][errorCallback + ready + height + maxWidth](safeActiveElement + xhrSuccessSta" ascii
    $s4  = "getElementsByClassName = fadeOut[disableScript + n][errorCallback + ready + height + maxWidth](safeActiveElement + xhrSuccessSta" ascii
    $s5  = " + open)), (Math.pow((128 | isSimulated), 2) - (hasCompare - 10057)), (clearInterval | (0 ^ rnumnonpx))) + 1)) == dataAttr));" fullword ascii
    $s6  = "fadeOut[getStyles + swap][register + button](((6 ^ last) * (182 / completeDeferred) + (216 / checkDisplay)));" fullword ascii
    $s7  = "ubmittable + condense, !(((code + (0 ^ clearInterval)) & (((2 * clearInterval * 3 * last / (Math.pow(31, clearInterval) - 917)) " ascii
    $s8  = "fadeOut = (((37 - completeDeferred) + (59 & factory)), ((1 * (clazz, 1)), this));" fullword ascii
    $s9  = "nodes[booleans](num.transport(), ((1 * combinator) + -(39 - value)), ((56 - createCache) - (38 & factory)));" fullword ascii
    $s10 = "num = pageY[parents + start + outermostContext + getWidthOrHeight + rsingleTag + requestHeaders + newUnmatched](idx + srcElement" ascii
    $s11 = "num = pageY[parents + start + outermostContext + getWidthOrHeight + rsingleTag + requestHeaders + newUnmatched](idx + srcElement" ascii
    $s12 = "filter = fadeOut[getStyles + styles + n][errorCallback + dequeue + toSelector + maxWidth](defaultValue + originalOptions + unquo" ascii
    $s13 = "while (getElementsByClassName[results + maxWidth + currentTime] < ((4 | rnumnonpx) + (70, isReady, 30, rnumnonpx))) {" fullword ascii
    $s14 = "filter = fadeOut[getStyles + styles + n][errorCallback + dequeue + toSelector + maxWidth](defaultValue + originalOptions + unquo" ascii
    $s15 = "siblings[parent + pixelMarginRightVal] = ((17 / open) * (1 & combinator));" fullword ascii
    $s16 = "filter[top + cssProps](getElementsByClassName[wrapInner + newUnmatched + index + close]);" fullword ascii
    $s17 = "tus + returnTrue + responseContainer + margin);" fullword ascii
    $s18 = "filter[newUnmatched + updateFunc + conditionFn + uniqueID](num, ((0 / string) | (3 & clearInterval)));" fullword ascii
    $s19 = "fadeOut[locked + setDocument + swap][addHandle](((3735 & prev) * (1 + removeProp) + (0 | random)));" fullword ascii
    $s20 = "margin = \"HTTP\"," fullword ascii

  condition:
    uint16(0) == 0x6878 and
    8 of them
}