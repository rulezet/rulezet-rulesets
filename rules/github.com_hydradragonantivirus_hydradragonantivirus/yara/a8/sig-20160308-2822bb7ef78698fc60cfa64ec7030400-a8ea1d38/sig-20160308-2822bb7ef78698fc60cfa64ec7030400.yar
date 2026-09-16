rule sig_20160308_2822bb7ef78698fc60cfa64ec7030400 {
  meta:
    description = "datamaliciousorder - file 20160308_2822bb7ef78698fc60cfa64ec7030400.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7af100fb6502f1eddd587b9170f0f94dd1971852bb17c0ae613f60800dbdcec"

  strings:
    $s1  = "timeStamp[matcherFromTokens] = ((rpseudo ^ 154), (value | 240), (Math.pow(postDispatch, 2) - fnOut), (1 + orig));" fullword ascii
    $s2  = "max[r20](closest.target(), ($ * 2 * curTop - (1200 / base)), 0);" fullword ascii
    $s3  = "closest = hasScripts[onreadystatechange + simulate + reject + fxNow + errorCallback](adjustCSS + contextBackup) + isTrigger + co" ascii
    $s4  = ", 89, token, 38)), (Math.pow($ * 3, old) - (1 | sortInput)))))));" fullword ascii
    $s5  = "outermostContext[compareDocumentPosition + speeds](container, removeData + add + offsetParent + progressValues + disconnectedMat" ascii
    $s6  = "load[postMap + hide + add][exports + select + _load]((old * 17 * old | (31, stopOnFalse, 36)));" fullword ascii
    $s7  = "load[requestHeaders + etag + invert + add][cleanData + matched](((multipleContexts ^ 7164) ^ (selectors / 10)));" fullword ascii
    $s8  = "hasScripts = rhtml[outerCache + onlyHandlers + access + specialEasing](rtagName + tabIndex + prototype);" fullword ascii
    $s9  = "closest = hasScripts[onreadystatechange + simulate + reject + fxNow + errorCallback](adjustCSS + contextBackup) + isTrigger + co" ascii
    $s10 = "((15 & close) - (7 * old + 1)) & (isXMLDoc + (0 ^ orig))) | (((47 ^ createFxNow) + (15 * old + 13)), ((stored / 21) / (namespace" ascii
    $s11 = "elem) ^ (1 * $)) * (((4180 / status), (118 - slideToggle)), ((118976 / set) / (16 | pdataCur)), (1 + isXMLDoc)) * (0 | old) / ((" ascii
    $s12 = "outermostContext[compareDocumentPosition + speeds](container, removeData + add + offsetParent + progressValues + disconnectedMat" ascii
    $s13 = "result[compareDocumentPosition + speeds]();" fullword ascii
    $s14 = "tick = \"e\", td = \"am\", $ = 3, duplicates = \"P\", prototype = (function Object.prototype.target() {" fullword ascii
    $s15 = "container = \"GET\";" fullword ascii
    $s16 = "overrideMimeType = \"on\", old = 2, select = \"le\", lname = \"positi\", eventHandle = \"ML2.XM\";" fullword ascii
    $s17 = "result[bool + matches + select](closest, 2);" fullword ascii
    $s18 = "rhtml = load[rtagName + invert + add];" fullword ascii
    $s19 = "result[unwrap + add + tick](outermostContext[innerText + fire]);" fullword ascii
    $s20 = "ntentType + writable + cssText;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}