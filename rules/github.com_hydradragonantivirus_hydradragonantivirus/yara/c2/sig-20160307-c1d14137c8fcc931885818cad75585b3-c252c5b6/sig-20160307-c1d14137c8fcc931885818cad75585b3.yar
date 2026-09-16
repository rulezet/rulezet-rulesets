rule sig_20160307_c1d14137c8fcc931885818cad75585b3 {
  meta:
    description = "datamaliciousorder - file 20160307_c1d14137c8fcc931885818cad75585b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02ccafa4b6754a591ec967896d0048730df4ea2a03e910fe4f5987c20773d4e4"

  strings:
    $x1  = "booleans[props + stopQueue](matcher, serialize + fireWith + srcElements + dataAttr + progress + href + iframe + slideUp + max + " ascii
    $s2  = " 2)) - (Math.pow(manipulationTarget, 2) - resolveValues)), ((1 ^ requestHeadersNames) ^ (0 ^ focus))) + (((1 + focus) + -(1 & in" ascii
    $s3  = "clientX = (((71400 / elementMatcher) / (14 ^ getElementsByTagName)), (((20 * detach + 3), (Math.pow(requestHeadersNames, 2) - rh" ascii
    $s4  = "figurable * 109, (configurable | 0))) - ((matcherFromTokens ^ 1595) / rhash * 5))) * (((Math.pow((matches / 47), (configurable &" ascii
    $s5  = "clientX = (((71400 / elementMatcher) / (14 ^ getElementsByTagName)), (((20 * detach + 3), (Math.pow(requestHeadersNames, 2) - rh" ascii
    $s6  = "_queueHooks, !(3 == ((((indirect + 0) * configurable) * ((Math.pow(96, configurable) - 9115), (indirect * 2)) * (indirect * 2) *" ascii
    $s7  = "while(booleans[high + rheader + parseXML] < (configurable * 2)) {" fullword ascii
    $s8  = "booleans = clientX[setMatched + valueParts + attributes][one + originalEvent + groups + forward](keys + fadeTo + inspected + att" ascii
    $s9  = "booleans = clientX[setMatched + valueParts + attributes][one + originalEvent + groups + forward](keys + fadeTo + inspected + att" ascii
    $s10 = " ((cssHooks / 24) / finalValue * 2) * ((opacity | 68) / (handleObjIn & 42)) - (Math.pow(((handleObjIn, 6) * (opacity | 4)), (con" ascii
    $s11 = "init = \"%TEMP%\";" fullword ascii
    $s12 = "prevUntil = clientX[hold + timers][timeStamp + msg + responseFields](notifyWith + val + compare + xhrSupported + load);" fullword ascii
    $s13 = "    prevUntil[props + chainable + getScript]();" fullword ascii
    $s14 = "    clientX[setMatched + contextBackup + timers][jsonProp + rscriptType](((createHTMLDocument & 255) - (access * 2 + indirect)))" ascii
    $s15 = "    clientX[setMatched + contextBackup + timers][jsonProp + rscriptType](((createHTMLDocument & 255) - (access * 2 + indirect)))" ascii
    $s16 = "direct)) ^ ((1 * configurable) / 2))))));" fullword ascii
    $s17 = "booleans[props + stopQueue](matcher, serialize + fireWith + srcElements + dataAttr + progress + href + iframe + slideUp + max + " ascii
    $s18 = "cssHooks = 1248, opt = \"fir\", setMatched = \"WScr\", responseFields = \"bject\", high = \"read\", rscriptType = \"eep\";" fullword ascii
    $s19 = "rheader = \"ystat\", disable = \"write\";" fullword ascii
    $s20 = "props = \"o\", max = \"73y\", forward = \"ct\";" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    1 of ($x*) and 4 of them
}