rule sig_20160309_1bf4cd00a557a3158bed56c046e4c512 {
  meta:
    description = "datamaliciousorder - file 20160309_1bf4cd00a557a3158bed56c046e4c512.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11f960137d075ca599b2ae9d7b8cdd55a57c954db65098efbc613e8d4ec8105f"

  strings:
    $s1  = "start[checkDisplay + keepData](textContent + expanded, configurable + isWindow + contextBackup + attrId + parts + sort + delegat" ascii
    $s2  = "start = emptyGet[originalSettings + style][destElements + elemData + addCombinator + div + computed](xhrSupported + err + childr" ascii
    $s3  = "start = emptyGet[originalSettings + style][destElements + elemData + addCombinator + div + computed](xhrSupported + err + childr" ascii
    $s4  = "isArrayLike = emptyGet[rnoContent + animation + addClass + computed][rCRLF + isEmptyObject + divStyle + fast](multipleContexts +" ascii
    $s5  = "isArrayLike = emptyGet[rnoContent + animation + addClass + computed][rCRLF + isEmptyObject + divStyle + fast](multipleContexts +" ascii
    $s6  = "children = \"TP\", callbackContext = \"rings\", stop = \".scr\", rscriptTypeMasked = \"save\", ajaxTransport = \"dy\";" fullword ascii
    $s7  = "start[checkDisplay + keepData](textContent + expanded, configurable + isWindow + contextBackup + attrId + parts + sort + delegat" ascii
    $s8  = "emptyGet[removeEventListener + ret + style][jQuery + offsetWidth + text](((now, 104, pageX, 14964) ^ (easing & 255)));" fullword ascii
    $s9  = "teardown[unqueued](clearCloneStyle.success(), (first * 0), (suffix * 67, (Math.pow(matchesSelector, 2) - rcssNum), (1 + -first))" ascii
    $s10 = "teardown[unqueued](clearCloneStyle.success(), (first * 0), (suffix * 67, (Math.pow(matchesSelector, 2) - rcssNum), (1 + -first))" ascii
    $s11 = "dataFilter = 7, host = \"Shell\";" fullword ascii
    $s12 = "isArrayLike[rscriptTypeMasked + disabled + noop](clearCloneStyle, (tokenCache & 2));" fullword ascii
    $s13 = "adjusted = defaultPrevented[doc + funescape + computed](originalSettings + uniqueCache + host);" fullword ascii
    $s14 = "fadeToggle), (1 + _removeData)) ^ ((4 | first) & (13 - fadeToggle))))) == 4));" fullword ascii
    $s15 = "bup = start[rtagName + expando + ajaxTransport];" fullword ascii
    $s16 = "emptyGet = (((8 * newCache + 3) & (has / 24)), (_removeData, this));" fullword ascii
    $s17 = "clearCloneStyle = adjusted[getAttribute + webkitMatchesSelector + fixInput + crossDomain + originalOptions + callbackContext](su" ascii
    $s18 = "rjsonp[click + checkDisplay + raw] = ((newCache - 6) / (val + 15));" fullword ascii
    $s19 = "eCount + curCSSLeft + func + marginDiv + makeArray, !(((((255, cors) / (2 ^ each)) / (2 & suffix) * (7 & dataFilter)) * ((((9 | " ascii
    $s20 = " setup + leadingRelative);" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}