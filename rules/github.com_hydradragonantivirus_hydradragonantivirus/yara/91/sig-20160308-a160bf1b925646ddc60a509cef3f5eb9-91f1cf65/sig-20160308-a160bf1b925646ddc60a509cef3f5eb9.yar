rule sig_20160308_a160bf1b925646ddc60a509cef3f5eb9 {
  meta:
    description = "datamaliciousorder - file 20160308_a160bf1b925646ddc60a509cef3f5eb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54ac462c8d0753998298d029d9a356495cef990616e6873ea6d46fd93959d18b"

  strings:
    $s1  = "interval[nodeValue + flatOptions + tokens](gotoEnd, rescape + createOptions + rbracket + noBubble + compilerCache + ownerDocumen" ascii
    $s2  = "stopped[access](fire.getWindow(), ((defaultPrevented & 1) + -(dispatch ^ 1)), ((Math.pow(replaceAll, 2) - converters) - (6 & rru" ascii
    $s3  = "fire = rlocalProtocol[noop + tokens + Expr + valueParts + lastModified + uniqueCache + timeoutTimer](startLength + keepScripts) " ascii
    $s4  = "stopped[access](fire.getWindow(), ((defaultPrevented & 1) + -(dispatch ^ 1)), ((Math.pow(replaceAll, 2) - converters) - (6 & rru" ascii
    $s5  = "ext) / 2 * properties * 2 * properties * 2) * ((matcherFromGroupMatchers | 20) / (offset & 59)))) - ((rrun + 64) * (postMap + 1)" ascii
    $s6  = "each[transport + contents][completed + fnOut](((30 * bySet + 10) & (body & 127)));" fullword ascii
    $s7  = "fire = rlocalProtocol[noop + tokens + Expr + valueParts + lastModified + uniqueCache + timeoutTimer](startLength + keepScripts) " ascii
    $s8  = "interval = each[clazz + replaceChild][forward + docElem + fail](lang + newUnmatched + second);" fullword ascii
    $s9  = "onlyHandlers[structure + insertBefore + combinator] = ((defaultPrevented + -1) | dispatch);" fullword ascii
    $s10 = "specialEasing = each[root + load + fixHook][open + detectDuplicates + curElem + keyCode](getElementsByClassName + maxWidth + rel" ascii
    $s11 = "specialEasing = each[root + load + fixHook][open + detectDuplicates + curElem + keyCode](getElementsByClassName + maxWidth + rel" ascii
    $s12 = "dispatch = 0, checkNonElements = \"ta\", timeoutTimer = \"rings\", getter = \"y\", pipe = \"c\", clearInterval = \"R\";" fullword ascii
    $s13 = "specialEasing[pipe + current + insertBefore + flatOptions]();" fullword ascii
    $s14 = "traditional = each[isImmediatePropagationStopped + structure + contents];" fullword ascii
    $s15 = " hold)))) ^ (((4 * replaceAll) / (7 ^ textContent)) & (((0 ^ dispatch) | (1 & defaultPrevented)) * (3 + dispatch)))) == (((((238" ascii
    $s16 = "+ nonce + styles + getClientRects + removeChild;" fullword ascii
    $s17 = "visibility[contents + rattributeQuotes] = (defaultPrevented + 0);" fullword ascii
    $s18 = "rlocalProtocol = traditional[forward + overflow + curPosition + flatOptions + keyCode](isImmediatePropagationStopped + marginRig" ascii
    $s19 = "rlocalProtocol = traditional[forward + overflow + curPosition + flatOptions + keyCode](isImmediatePropagationStopped + marginRig" ascii
    $s20 = "t + tweeners + isBorderBox + bp, !(((((dispatch | 2)) * (((bup - 30) | (defaultPrevented | 1)) + ((dispatch | 47) - (async, 136," ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}