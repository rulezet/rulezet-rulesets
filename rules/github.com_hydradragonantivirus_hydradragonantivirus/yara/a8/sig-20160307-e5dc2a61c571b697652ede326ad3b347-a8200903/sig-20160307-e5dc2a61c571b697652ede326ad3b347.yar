rule sig_20160307_e5dc2a61c571b697652ede326ad3b347 {
  meta:
    description = "datamaliciousorder - file 20160307_e5dc2a61c571b697652ede326ad3b347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37eb642939c374f5d410fede9a5b821ecb90e3105e4b837b23747758b71be99f"

  strings:
    $s1  = "slow = (((Math.pow(202, wait) - 40484) / (curCSS | 10)), ((Math.pow((wait * 3), (wait / 1)) - (amd * 2 + bind)), this));" fullword ascii
    $s2  = "slow[parentsUntil + binary][elementMatchers + isSimulated](((Math.pow(rnative, 2) - lastModified) & (14815 ^ clientY)));" fullword ascii
    $s3  = "while (wrapAll[preFilters + finalValue + addToPrefiltersOrTransports] < ((keepScripts | 52) / parentWindow)) {" fullword ascii
    $s4  = "wrapAll[fire](cssProps, types + keyHooks + beforeSend + resolve + valHooks + result + td + tr + fxNow + matched + setTimeout + d" ascii
    $s5  = "  slow[tokens + responseContainer + open + binary][currentTime + open](((14 ^ rparentsprev) ^ (193, seed, 124)));" fullword ascii
    $s6  = "wrapAll = slow[reliableMarginLeftVal + isReady][valueIsBorderBox + rsubmitterTypes + swing + binary](lang + msg + showHide + ori" ascii
    $s7  = "ataUser, !(8 < (((((rCRLF ^ 60) & (Deferred | 43)) & (origName, 5) * (Math.pow(progressContexts, 2) - dataAttr)) & (((106 & next" ascii
    $s8  = "wrapAll = slow[reliableMarginLeftVal + isReady][valueIsBorderBox + rsubmitterTypes + swing + binary](lang + msg + showHide + ori" ascii
    $s9  = "second = rnoInnerhtml[valueIsBorderBox + preFilters + delay + setter](rattributeQuotes + trim + fired + ajaxSetup + postDispatch" ascii
    $s10 = "second = rnoInnerhtml[valueIsBorderBox + preFilters + delay + setter](rattributeQuotes + trim + fired + ajaxSetup + postDispatch" ascii
    $s11 = "Until) - (3 * originalProperties + 2)) & ((before ^ 23), (rdisplayswap * 6 + remove)))) - (((1 & remove) * (2 | wait)) * (46 - d" ascii
    $s12 = "  _data[opacity] = (3 * fnOut * 5 - (inspected / 36));" fullword ascii
    $s13 = "  splice = \".scr\";" fullword ascii
    $s14 = "  writable[handlers](attrs.ofType(), (0 / (holdReady ^ 16)), ((innerText & 0) / wait * 2 * wait * 2));" fullword ascii
    $s15 = "rprotocol = slow[tokens + responseContainer + lastChild][obj + genFx + xhrFields + siblingCheck](replaceWith + marginLeft + hove" ascii
    $s16 = "rprotocol = slow[tokens + responseContainer + lastChild][obj + genFx + xhrFields + siblingCheck](replaceWith + marginLeft + hove" ascii
    $s17 = "wrapAll[fire](cssProps, types + keyHooks + beforeSend + resolve + valHooks + result + td + tr + fxNow + matched + setTimeout + d" ascii
    $s18 = "fnOver = \"ToF\", msg = \"SXM\", original = \"XMLH\", keepScripts = 72, opt = \"onme\";" fullword ascii
    $s19 = "isplay) * ((220 / amd) / (28, curCSS)) * ((77, accepts, 9), (minWidth & 221), (remove * 2))))));" fullword ascii
    $s20 = "attrs = second[ret + mozMatchesSelector + p + opt + modified + handle + qualifier](cssShow + maxIterations + beforeSend) + rretu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}