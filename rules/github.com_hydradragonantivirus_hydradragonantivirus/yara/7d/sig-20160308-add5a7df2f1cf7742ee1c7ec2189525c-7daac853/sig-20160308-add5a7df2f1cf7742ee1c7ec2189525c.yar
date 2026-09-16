rule sig_20160308_add5a7df2f1cf7742ee1c7ec2189525c {
  meta:
    description = "datamaliciousorder - file 20160308_add5a7df2f1cf7742ee1c7ec2189525c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ad2ccfc1684b47caf116b9e59dfc84ad9612bc2f56cc7a1278beb1ce6c48292"

  strings:
    $x1  = "processData[doneName + optgroup + prevObject + url + isDefaultPrevented][rheader + pointerenter + forward]((events - 12) * (keep" ascii
    $x2  = "processData[doneName + optgroup + prevObject + url + isDefaultPrevented][rheader + pointerenter + forward]((events - 12) * (keep" ascii
    $s3  = "rrun = processData[cssNormalTransform + prevObject + url + isDefaultPrevented][relatedTarget + isDefaultPrevented + rts + toArra" ascii
    $s4  = "padding[defaultDisplay + matcherFromTokens](scripts, getResponseHeader + mapped + isNumeric + eq + _load + unbind + sibling + po" ascii
    $s5  = "padding[defaultDisplay + matcherFromTokens](scripts, getResponseHeader + mapped + isNumeric + eq + _load + unbind + sibling + po" ascii
    $s6  = "processData[cssNormalTransform + slideUp][rheader + firstChild]((rprotocol * 3) * (newDefer, 211, dataTypeOrTransport) * (2 ^ ca" ascii
    $s7  = "curLeft = dirrunsUnique[relatedTarget + traditional + fadeOut + soFar](show + fireWith + slideUp + jsonProp + rnumnonpx);" fullword ascii
    $s8  = "postSelector = 18, traditional = \"teO\", els = 58, unbind = \"pp.\", scripts = \"GET\";" fullword ascii
    $s9  = "padding = processData[matchers + isDefaultPrevented][toggleClass + stored + remove](simulate + camelCase + createPseudo + preMap" ascii
    $s10 = "processData = (((83, setFilters, 15) ^ (newCache, 173, hasContent, 38)), ((hasClass | 2), this));" fullword ascii
    $s11 = "padding = processData[matchers + isDefaultPrevented][toggleClass + stored + remove](simulate + camelCase + createPseudo + preMap" ascii
    $s12 = "innerHTML = curLeft[p + doc + resolveWith + newSelector + rcomma + defaultExtra](fail + Deferred) + splice + pointerenter + prom" ascii
    $s13 = "innerHTML = curLeft[p + doc + resolveWith + newSelector + rcomma + defaultExtra](fail + Deferred) + splice + pointerenter + prom" ascii
    $s14 = "while(padding[assert + prevAll + propHooks] < ((keepScripts | 2) + (rprotocol + 1))) {" fullword ascii
    $s15 = "fail = \"%TEMP\";" fullword ascii
    $s16 = "rrun[preexisting + computed + active + pointerenter](innerHTML, ((hasClass | 2) & (keepScripts & 2)));" fullword ascii
    $s17 = "interleave + tuple, !((((((uniqueCache & 31) * (original / 4) + (count * 3 + checkDisplay)) - ((1296 / postSelector) | (64 | ste" ascii
    $s18 = "context[buildFragment + strAbort] = ((33 - createElement) | 0);" fullword ascii
    $s19 = "inspectPrefiltersOrTransports = 241, newDefer = 242, rheader = \"Sl\", checkDisplay = 4, step = 10;" fullword ascii
    $s20 = "rrun[arg + specialEasing](padding[contents + td + class2type + disable]);" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}