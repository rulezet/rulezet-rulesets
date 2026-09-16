rule sig_20160308_0177638d46bae7daae67cc4f8d12d50c {
  meta:
    description = "datamaliciousorder - file 20160308_0177638d46bae7daae67cc4f8d12d50c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3853ecba252a86f159dacbd32f7c4ae05b72970f54315a47d56d731ca109419e"

  strings:
    $s1  = "marginLeft[stopPropagation](inspectPrefiltersOrTransports + setGlobalEval, propFilter + window + initial + qsa + simple + amd + " ascii
    $s2  = "targets + postSelector, !(((((17 - options) & (1 * parsed)) & ((99 / contentType) / (Math.pow(8, removeClass) - 53))) | ((((whit" ascii
    $s3  = "removeProp = noCloneChecked[overflowX + not][matchedCount + handleObj + contextBackup](postDispatch + keepScripts + rpseudo + to" ascii
    $s4  = "addClass[map + getWidthOrHeight + rhash] = ((originalEvent - 14), (Math.pow(preDispatch, 2) - param), (465 - reset), (0 | preFil" ascii
    $s5  = "addClass[map + getWidthOrHeight + rhash] = ((originalEvent - 14), (Math.pow(preDispatch, 2) - param), (465 - reset), (0 | preFil" ascii
    $s6  = "empty = 45, contentType = 9, initialInUnit = \"t\", targets = \"uh54gb\";" fullword ascii
    $s7  = "memory = \"%TEMP%\";" fullword ascii
    $s8  = "keepScripts = \"DO\", preDispatch = 52, map = \"pos\", rhash = \"on\";" fullword ascii
    $s9  = "start[inspected](time.firing(), (1 + -parsed), (1 & (genFx, 31, preFilters)));" fullword ascii
    $s10 = "marginLeft[stopPropagation](inspectPrefiltersOrTransports + setGlobalEval, propFilter + window + initial + qsa + simple + amd + " ascii
    $s11 = "removeProp[factory](marginLeft[defaultValue + truncate + pos + scripts + adjustCSS + fontWeight]);" fullword ascii
    $s12 = "removeProp[textContent + isSuccess + rclass](time, (2 | preFilters));" fullword ascii
    $s13 = "while(marginLeft[checkContext + fontWeight + structure] < (preFilters | 2) * (parsed * 2)) {" fullword ascii
    $s14 = "time = accepts[children + isWindow + pattern + arg + firstChild + fnOut](memory + using) + rbracket + fn + outermostContext;" fullword ascii
    $s15 = "harCode) * (4 / removeClass)) - (((71 - raw) - (686 / html)) - ((48 | name), (140 | empty), (359 - conditionFn), (0 / stateVal))" ascii
    $s16 = "noCloneChecked = (((17 * removeClass + 7) * (parsed + 3) + (selector * 3 + parsed)), (((142 - overflow) / (29 ^ removeClass)), t" ascii
    $s17 = "noCloneChecked = (((17 * removeClass + 7) * (parsed + 3) + (selector * 3 + parsed)), (((142 - overflow) / (29 ^ removeClass)), t" ascii
    $s18 = "token = \".Stre\"," fullword ascii
    $s19 = "stop = \"Run\";" fullword ascii
    $s20 = "overflow = 80;" fullword ascii

  condition:
    uint16(0) == 0x7261 and
    8 of them
}