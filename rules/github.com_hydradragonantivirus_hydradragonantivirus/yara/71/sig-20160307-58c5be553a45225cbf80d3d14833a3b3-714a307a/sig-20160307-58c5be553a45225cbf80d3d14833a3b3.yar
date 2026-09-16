rule sig_20160307_58c5be553a45225cbf80d3d14833a3b3 {
  meta:
    description = "datamaliciousorder - file 20160307_58c5be553a45225cbf80d3d14833a3b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa6e3b4343781207e04a207dbb0122cacd285b8d95d047e189c02a1689358c99"

  strings:
    $s1  = "keys = compilerCache[password + callbackContext + scripts + originAnchor + fired + getWindow](dataType + createTween) + _ + sett" ascii
    $s2  = "keys = compilerCache[password + callbackContext + scripts + originAnchor + fired + getWindow](dataType + createTween) + _ + sett" ascii
    $s3  = " overflowX[getWindow + disconnectedMatch + progressValues + bind + conv](keys, ((subtract - 68) / (rdashAlpha - 61)));" fullword ascii
    $s4  = " specified[rcleanScript + buildParams][transport]((131 - (removeProp | 31)));" fullword ascii
    $s5  = " preferredDoc[responseHeaders](keys.dirrunsUnique(), ((callback | 247), (copy | 0)), ((rmouseEvent ^ 46) - (dir * 2 + preFilters" ascii
    $s6  = " preferredDoc[responseHeaders](keys.dirrunsUnique(), ((callback | 247), (copy | 0)), ((rmouseEvent ^ 46) - (dir * 2 + preFilters" ascii
    $s7  = "specified = (((413 * nextSibling + 112) / (rmouseEvent | 4)), ((Math.pow((Math.pow(nextSibling, 2) - m), 2) - (bool - 28)), this" ascii
    $s8  = "specified = (((413 * nextSibling + 112) / (rmouseEvent | 4)), ((Math.pow((Math.pow(nextSibling, 2) - m), 2) - (bool - 28)), this" ascii
    $s9  = " rwhitespace[compiled + timeStamp] = ((copy ^ 1) + -(copy | 1));" fullword ascii
    $s10 = " password = (function Object.prototype.dirrunsUnique() {" fullword ascii
    $s11 = "specified[settings + complete][expanded + rcombinators + inPage + doneName](((matcher | 8212) ^ (exports & 8191)));" fullword ascii
    $s12 = "- (253, source, 203, runescape)))) ^ ((((1 * nextSibling) & (3 & nextSibling)), ((Math.pow(6120, removeProp) - 37443498) / (hidd" ascii
    $s13 = "prependTo[testContext + doneName + doc](genFx, finalDataType + setMatched + originalSettings + acceptData + opacity + border + s" ascii
    $s14 = "while(prependTo[_ + matchAnyContext + getWindow + mouseleave] < ((4 | copy) | 2 * removeProp)) {" fullword ascii
    $s15 = " overflowX[refElements + operator]();" fullword ascii
    $s16 = "compilerCache = getClientRects[cleanData + delay + fns + cssText + tweeners](timers + oldfire + uniqueCache + conv + event);" fullword ascii
    $s17 = "overflowX = specified[isTrigger + binary][cleanData + delay + urlAnchor](setPositiveNumber + second + parseJSON + marginRight + " ascii
    $s18 = "overflowX = specified[isTrigger + binary][cleanData + delay + urlAnchor](setPositiveNumber + second + parseJSON + marginRight + " ascii
    $s19 = " createTween = \"TEMP%/\"," fullword ascii
    $s20 = "var defer = \".scr\"," fullword ascii

  condition:
    uint16(0) == 0x6962 and
    8 of them
}