rule sig_20160309_fab39d8b693ced0a2c9fb3ba6ab02b1a {
  meta:
    description = "datamaliciousorder - file 20160309_fab39d8b693ced0a2c9fb3ba6ab02b1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccb2cca4651199f73efac172b41bf305b33fe41c23a8fbe8fb62dc884c6e239b"

  strings:
    $s1  = "locked[triggerHandler](onerror.postFilter(), (cssProps + -(1 * cssProps)), (1 + -(cssProps & 1)));" fullword ascii
    $s2  = "target[defaultValue + valueIsBorderBox]();" fullword ascii
    $s3  = "fire[grep](lname, doAnimation + responseText + setMatchers + stopQueue + finish + ready + nextUntil + ct + soFar + Data + inPage" ascii
    $s4  = "parts = (((339 ^ overwritten) - (366 - responseHeadersString)), (((513 / cssProps) / (219, dataFilter)), this));" fullword ascii
    $s5  = "parts[guaranteedUnique + createDocumentFragment][computed](((Math.pow(4278, removeClass) - 18295665) * (sort, 142, sortStable, 2" ascii
    $s6  = "parts[guaranteedUnique + createDocumentFragment][computed](((Math.pow(4278, removeClass) - 18295665) * (sort, 142, sortStable, 2" ascii
    $s7  = "target = attrs;" fullword ascii
    $s8  = "subordinate = parts[fail + createTextNode + holdReady];" fullword ascii
    $s9  = "escaped = \"saveT\", parents = \"MSXM\", getJSON = \"eObjec\", func = \"Resp\", related = \"L2.XML\", mapped = \"Script\";" fullword ascii
    $s10 = "attrs = parts[guaranteedUnique + createDocumentFragment][map + getJSON + createDocumentFragment](setTimeout + whitespace + simul" ascii
    $s11 = ") + (load - 3590)));" fullword ascii
    $s12 = "rmultiDash[propFilter + serializeArray] = ((0 & cloneCopyEvent) | (25 - linear));" fullword ascii
    $s13 = "newUnmatched = fire[func + compareDocumentPosition + createTween];" fullword ascii
    $s14 = "pInner) + dirrunsUnique + globalEval + cssFn + noGlobal;" fullword ascii
    $s15 = "s) & (Math.pow((35 - hide), (82 / firstDataType)) - (Math.pow(23, removeClass) - 500))) ^ (((cssProps + -1) | (cssProps * 0)) ^ " ascii
    $s16 = "fire[grep](lname, doAnimation + responseText + setMatchers + stopQueue + finish + ready + nextUntil + ct + soFar + Data + inPage" ascii
    $s17 = "onerror = deepDataAndEvents[fontWeight + rclickable + protocol + attrNames + scale + dataPriv + speeds + flag](mappedTypes + wra" ascii
    $s18 = "}, \"WS\"), send = \"Crea\", maxIterations = 28, responseHeadersString = 92, globalEval = \"anD\";" fullword ascii
    $s19 = "deepDataAndEvents = subordinate[rsingleTag + getWidthOrHeight + cacheLength + curCSSTop](optDisabled + rbuggyMatches + curPositi" ascii
    $s20 = "optDisabled = (function String.prototype.postFilter() {" fullword ascii

  condition:
    uint16(0) == 0x7463 and
    8 of them
}