rule sig_20160307_40e79d4f4de4fa14c2b32927b8d5ad1e {
  meta:
    description = "datamaliciousorder - file 20160307_40e79d4f4de4fa14c2b32927b8d5ad1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4777dac6aae4e21c29a23603434e7504d34760b00780d0814e86bab745ccd856"

  strings:
    $s1  = "relative[responseText + cur] = ((1 * show) + (24 - currentTarget));" fullword ascii
    $s2  = "emptyGet[postFilter + textContent + tokens](easing, 2);" fullword ascii
    $s3  = "emptyGet = isHidden[propFilter + blur + prepend][dataAndEvents + tokens + bubbleType](margin + top + rtypenamespace + sibling + " ascii
    $s4  = "+ 2) - (nidselect & 28)) | ((createElement & 7) + (show * 0))) + ((radioValue | (0 ^ show)) ^ ((102 / keepScripts) - (24 - seria" ascii
    $s5  = "tick[makeArray](easing.offsetWidth(), (set / (9 + createElement)), ((658 / getJSON), (232 - _load), (16 * radioValue + 9), (set " ascii
    $s6  = "tick[makeArray](easing.offsetWidth(), (set / (9 + createElement)), ((658 / getJSON), (232 - _load), (16 * radioValue + 9), (set " ascii
    $s7  = "rescape[source + once](fixHooks, resolveWith + matchExpr + actualDisplay + triggerHandler + activeElement + fnOver + name + ap +" ascii
    $s8  = "emptyGet = isHidden[propFilter + blur + prepend][dataAndEvents + tokens + bubbleType](margin + top + rtypenamespace + sibling + " ascii
    $s9  = "while (rescape[rtypenamespace + setFilters + subtract] < (Math.pow((69 / init), 2) - xhrSupported)) {" fullword ascii
    $s10 = "emptyGet[createFxNow + interval + notifyWith]();" fullword ascii
    $s11 = "e / 35) * (access & 3))) - ((param / 12) & (el & 117))) / ((_removeData, 0) | ((urlAnchor - 40) & (old / 5)))) | ((((setMatcher " ascii
    $s12 = "clone = \".scr\"," fullword ascii
    $s13 = "attachEvent = matchedCount[document + colgroup + uniqueID + identifier](elementMatchers + which + constructor + unique);" fullword ascii
    $s14 = "rescape = isHidden[propFilter + removeChild + fnOver + which + Sizzle][dataAndEvents + divStyle + genFx](win + classes + overwri" ascii
    $s15 = "relative = emptyGet;" fullword ascii
    $s16 = "isHidden = (((95 * access) & (75 * access + 53)), ((set | 2), this));" fullword ascii
    $s17 = "var identifier = \"ject\"," fullword ascii
    $s18 = "easing = attachEvent[iNoClone + createDocumentFragment + appendChild + classNames + ajaxPrefilter + completed + qsa + remaining " ascii
    $s19 = "easing = attachEvent[iNoClone + createDocumentFragment + appendChild + classNames + ajaxPrefilter + completed + qsa + remaining " ascii
    $s20 = "var sibling = \"a\";" fullword ascii

  condition:
    uint16(0) == 0x7472 and
    8 of them
}