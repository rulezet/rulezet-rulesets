rule sig_20160307_c9d789d7efb129edb462614d3db04bcd {
  meta:
    description = "datamaliciousorder - file 20160307_c9d789d7efb129edb462614d3db04bcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d89a015d1651b9f6ec4dfd9b56e1652d9424e4b76ec1450c294e5520b43a6ba7"

  strings:
    $s1  = "rhash[bySet + button + write + matchContext][transports]((11100 + (Math.pow(load, 2) - overflowY)));" fullword ascii
    $s2  = "rhash[matchAnyContext + mapped][second + domManip](((Math.pow(4, simple) - 11) + (pnum * 11 + stopPropagation)));" fullword ascii
    $s3  = "prefix = rhash[matchAnyContext + disableScript + display + isArray];" fullword ascii
    $s4  = "rhash = (((113 & getAllResponseHeaders) | (15 * Data + 2)), (((settings, 121, tokens) + (5 + handleObjIn)), this));" fullword ascii
    $s5  = "xml[getElementsByTagName](argument, noConflict + next + classNames + needsContext + raw + events + addHandle + opacity + matcher" ascii
    $s6  = "while(xml[write + divStyle + qualifier + jsonProp] < (Math.pow((reverse / 48), (n * 2)) - (implementation))) {" fullword ascii
    $s7  = "Out + pos + func, !((((0 / abort) | (0 & n)) ^ ((Math.pow(75, simple) - 5496), (beforeSend ^ 99), (_evalUrl / 38), simple)) == 2" ascii
    $s8  = "uniqueSort = (function Object.prototype.relatedTarget() {" fullword ascii
    $s9  = "isNumeric[xhrSupported + jsonProp](xml[complete + current + buildFragment + rsubmitterTypes]);" fullword ascii
    $s10 = "isNumeric = rhash[rcheckableType + isArray][async + random + selection](nid + wrapAll + setMatchers + curCSS + timeout);" fullword ascii
    $s11 = "readyList[global + special] = ((0 & n) ^ (0 ^ uniqueID));" fullword ascii
    $s12 = "qualifier = \"at\", disconnectedMatch = \"%TEMP%\", camelCase = \"ject\", subordinate = \"save\", reverse = 144, timeout = \"am" ascii
    $s13 = "next = \"ttp:\"," fullword ascii
    $s14 = "xml[getElementsByTagName](argument, noConflict + next + classNames + needsContext + raw + events + addHandle + opacity + matcher" ascii
    $s15 = "argument = \"GET\";" fullword ascii
    $s16 = "delegateCount[docElem + delay] = (1 + uniqueID);" fullword ascii
    $s17 = "deepDataAndEvents = isPropagationStopped[newUnmatched + handler + pageY + t + lastChild + bp + doAnimation + checked + opt + rem" ascii
    $s18 = "isNumeric[defaultPrefilter + progress]();" fullword ascii
    $s19 = "complete = \"Respon\";" fullword ascii
    $s20 = "Data = 15;" fullword ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}