rule sig_20160309_63634853f9593c65c890b8a8c037083d {
  meta:
    description = "datamaliciousorder - file 20160309_63634853f9593c65c890b8a8c037083d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0622af6118f730ab71b06afa0e3e1acd3763751512c38d1ce6bed1e642f00f1b"

  strings:
    $x1  = "getComputedStyle[rcombinators + onreadystatechange](proxy + hasOwnProperty, active + getStyles + fail + wrapAll + time + startTi" ascii
    $s2  = "eJSON) - (Math.pow((159, ifModified, 25), (targets * 2)) - (elementMatchers & 1019))) + (((targets * 1) & (targets * 1)) - (prop" ascii
    $s3  = "getComputedStyle = mozMatchesSelector[dirruns + rtagName][noConflict + globalEval + thead + tweens](swap + createButtonPseudo + " ascii
    $s4  = "getComputedStyle[rcombinators + onreadystatechange](proxy + hasOwnProperty, active + getStyles + fail + wrapAll + time + startTi" ascii
    $s5  = "mozMatchesSelector = (((18 ^ rbracket), (1332 / delegateTarget)), (((162, rscriptType) / (13 & preFilter)), this));" fullword ascii
    $s6  = "radio[getScript] = (targets & (110, elem, 1));" fullword ascii
    $s7  = "getComputedStyle = mozMatchesSelector[dirruns + rtagName][noConflict + globalEval + thead + tweens](swap + createButtonPseudo + " ascii
    $s8  = "createTextNode = mozMatchesSelector[dirruns + rtagName][b + attrHandle + num](overrideMimeType + implementation + setGlobalEval)" ascii
    $s9  = "createTextNode = mozMatchesSelector[dirruns + rtagName][b + attrHandle + num](overrideMimeType + implementation + setGlobalEval)" ascii
    $s10 = "runescape = getComputedStyle[udataOld + cssText + dispatch + parentNode];" fullword ascii
    $s11 = "slideUp = subtract[max + mouseenter + andSelf + isReady + fireWith + matchesSelector + matchIndexes](JSON + ownerDocument) + fil" ascii
    $s12 = "scrollTo + structure + keepScripts);" fullword ascii
    $s13 = "setGlobalEval = \"m\", isReady = \"nmen\", xhrFields = 9, scrollTop = \"c\", thead = \"b\", select = \"W\";" fullword ascii
    $s14 = "slideUp = subtract[max + mouseenter + andSelf + isReady + fireWith + matchesSelector + matchIndexes](JSON + ownerDocument) + fil" ascii
    $s15 = "bind = mozMatchesSelector[select + origName + namespaces + fireWith];" fullword ascii
    $s16 = "subtract = bind[noConflict + finalDataType + percent + filters](define + createComment + focusin + clientTop);" fullword ascii
    $s17 = "safeActiveElement = 182, rrun = \"send\", nType = \"cr\", Symbol = 5, createComment = \"t.Sh\";" fullword ascii
    $s18 = "createTextNode[setMatchers + evt + disabled](slideUp, ((safeActiveElement, 52, msg, 2) | propFix));" fullword ascii
    $s19 = "string[buildParams + hasData + code] = (propFix | 0);" fullword ascii
    $s20 = "next = \"Run\";" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    1 of ($x*) and 4 of them
}