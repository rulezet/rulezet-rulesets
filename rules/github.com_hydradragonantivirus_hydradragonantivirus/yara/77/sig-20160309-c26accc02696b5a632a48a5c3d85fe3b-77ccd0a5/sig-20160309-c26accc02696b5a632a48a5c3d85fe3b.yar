rule sig_20160309_c26accc02696b5a632a48a5c3d85fe3b {
  meta:
    description = "datamaliciousorder - file 20160309_c26accc02696b5a632a48a5c3d85fe3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f2ab9fb8994d69e09aceb7d690a3719047dea96f8f4b62a34aff2d79a77f291"

  strings:
    $s1  = "curCSSTop = (((269 - pixelPosition) & (148 - options)), (((Math.pow(16, wait) - 238) & (getScript - 28)), this));" fullword ascii
    $s2  = "exports[origName + byElement + curCSSLeft](dataPriv + inArray, clearInterval + excess + sortStable + undelegate + attachEvent + " ascii
    $s3  = "trAbort - 3) & getWidthOrHeight)), (((1 + context) & (22 - rts)) + ((80 - keyHooks), (2 * wait + 1))))) == lastModified));" fullword ascii
    $s4  = " addEventListener) + testContext + ready + rreturn + headers;" fullword ascii
    $s5  = "identifier = defaultDisplay[pointerenter + byElement + extend + conv2 + init + before + callbackContext + apply](firing + seed +" ascii
    $s6  = "- 33)) + ((node - 38) ^ (matcherIn, 33, name, 5))) & (((hasContent / 23) - (handleObj / 28)) & ((curTop + 129) / (factory & 25))" ascii
    $s7  = "unloadHandler = exports[triggerHandler + origName + disable + getElementsByTagName];" fullword ascii
    $s8  = "triggered[matchIndexes + cssText + marginLeft](identifier, ((1 & getWidthOrHeight) ^ 2));" fullword ascii
    $s9  = "ready = \"ndTo\", getScript = 54;" fullword ascii
    $s10 = " stop + select + defaultValue + restoreScript);" fullword ascii
    $s11 = "exports = curCSSTop[response + setOffset][contextBackup + relative + crossDomain](removeClass + hasCompare + optall + qsaError +" ascii
    $s12 = "exports = curCSSTop[response + setOffset][contextBackup + relative + crossDomain](removeClass + hasCompare + optall + qsaError +" ascii
    $s13 = ")) & (((wait * 2 * wait * 2 ^ (getWidthOrHeight | 9)) ^ ((split ^ 140) / (lastModified * 2 + wait))), ((1 * (context ^ 0)) ^ ((s" ascii
    $s14 = "triggered = curCSSTop[response + setOffset][responses + clearTimeout + statusText + originAnchor](createFxNow + pixelMarginRight" ascii
    $s15 = "curCSSTop[handleObjIn + removeProp][url](((createDocumentFragment - 2420) * (filters, 73, wait) + 2 * wait * 523 * wait));" fullword ascii
    $s16 = "window[rlocalProtocol + clearCloneStyle] = ((1 * getWidthOrHeight) | (1 * getWidthOrHeight));" fullword ascii
    $s17 = "mouseenter[rCRLF](identifier.fx(), ((1 & context) & 0), ((context) * (0 ^ getWidthOrHeight)));" fullword ascii
    $s18 = "exports[origName + byElement + curCSSLeft](dataPriv + inArray, clearInterval + excess + sortStable + undelegate + attachEvent + " ascii
    $s19 = "defaultDisplay = position[doneName + preFilters + clientX + toggleClass + clientLeft + removeProp](jsonpCallback + appendChild +" ascii
    $s20 = "getWidthOrHeight = 0, inArray = \"T\", byElement = \"p\", statusText = \"j\", name = 93, relative = \"teObje\";" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}