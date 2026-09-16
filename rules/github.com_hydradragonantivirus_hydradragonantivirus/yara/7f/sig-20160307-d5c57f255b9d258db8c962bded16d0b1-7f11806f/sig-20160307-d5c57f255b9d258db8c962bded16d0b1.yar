rule sig_20160307_d5c57f255b9d258db8c962bded16d0b1 {
  meta:
    description = "datamaliciousorder - file 20160307_d5c57f255b9d258db8c962bded16d0b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16a8cd2f02577646d8d153430f84d158b9512ad3df6c4dea3a0604dd4ca4589d"

  strings:
    $s1  = "checkClone = ((Math.pow((83 + keepScripts), (76, dirruns)) - (22191 + contexts)), ((Math.pow((17 - contentType), (1 ^ onload)) -" ascii
    $s2  = "toggle = checkClone[processData + getAllResponseHeaders + parsed + rfxtypes][byElement + mouseleave + rfxtypes](hide + iframe + " ascii
    $s3  = "toggle = checkClone[processData + getAllResponseHeaders + parsed + rfxtypes][byElement + mouseleave + rfxtypes](hide + iframe + " ascii
    $s4  = "toggle[async + parsed + node](propFix + transports, preFilters + matchContext + when + unmatched + addCombinator + checkOn + set" ascii
    $s5  = "* ((wrapAll / 11), (hasClass ^ 120), (responses ^ 2), (readyList - 35)))) - (((document | 0) ^ (contentType | 0)) ^ ((contentTyp" ascii
    $s6  = "wrap[seekingTransport + dataType + divStyle](crossDomain, ((dirruns & 2) + (contentType * 0)));" fullword ascii
    $s7  = "while(toggle[append + rfxtypes + extra] < ((71, contentType) ^ (17 - timeoutTimer))) {" fullword ascii
    $s8  = "old[progressValues + Symbol] = (1 * (contentType + -1));" fullword ascii
    $s9  = "augmentWidthOrHeight[cos](crossDomain.Expr(), (contentType * (6, constructor, 113, document)), ((32 | setGlobalEval) - (48 | doc" ascii
    $s10 = "augmentWidthOrHeight[cos](crossDomain.Expr(), (contentType * (6, constructor, 113, document)), ((32 | setGlobalEval) - (48 | doc" ascii
    $s11 = "crossDomain = factory[outermostContext + contextBackup + rootjQuery + node + rtypenamespace + rfxtypes + initialInUnit + fontWei" ascii
    $s12 = "factory = isReady[optDisabled + defaultPrefilter + getById + clearQueue](pseudo + curLeft + triggered + dataAndEvents);" fullword ascii
    $s13 = "checkClone[callback + getScript + rfxtypes][elemData](((115 + getResponseHeader), 11 * last, (11 * ajaxHandleResponses + 1)));" fullword ascii
    $s14 = "checkClone[pseudo + isSimulated][disable + rcleanScript](((subtract & 16383) & nid * 2 * onload));" fullword ascii
    $s15 = "dataTypeOrTransport + maxWidth + root);" fullword ascii
    $s16 = "toggle[async + parsed + node](propFix + transports, preFilters + matchContext + when + unmatched + addCombinator + checkOn + set" ascii
    $s17 = "wrap[jsonp + hasScripts]();" fullword ascii
    $s18 = "ght + serialize](rwhitespace + global) + delegateType + settings + clientX + addGetHookIf + setAttribute + structure + dataShow " ascii
    $s19 = " (497 - done)), this));" fullword ascii
    $s20 = "linear[idx + defaultPrefilter] = ((32 & dataFilter) - (31 & isBorderBox));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}