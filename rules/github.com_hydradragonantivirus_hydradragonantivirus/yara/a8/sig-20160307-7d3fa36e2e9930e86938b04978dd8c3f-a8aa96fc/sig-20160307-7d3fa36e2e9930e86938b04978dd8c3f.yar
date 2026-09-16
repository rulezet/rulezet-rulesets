rule sig_20160307_7d3fa36e2e9930e86938b04978dd8c3f {
  meta:
    description = "datamaliciousorder - file 20160307_7d3fa36e2e9930e86938b04978dd8c3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38820e925564e1ceeaa32217bd1ba419f111fe399c893efd01f63aa13a8bbdbf"

  strings:
    $s1  = "append[getClientRects](genFx, prevObject + superMatcher + htmlPrefilter + dataTypeExpression + extra + tr + removeProp + srcElem" ascii
    $s2  = "seed = dataAndEvents[marginRight + createElement + xhrSupported + noBubble + defineProperty + rcheckableType + unbind + offsetHe" ascii
    $s3  = "elemData[remove + getResponseHeader + success][innerText + exports + ret]((5 | msFullscreenElement) * (48 / attrHandle) * (1 ^ m" ascii
    $s4  = "append = elemData[remove + getResponseHeader + success][max + isWindow + hasFocus](uniqueSort + hasContent + rts + nativeStatusT" ascii
    $s5  = "ents, !((((Math.pow((rheaders & 7), ((hasClass / 33) - (maxIterations ^ 56))) - ((runescape * 6) + timer)) / (((1 * defaultPreve" ascii
    $s6  = "append = elemData[remove + getResponseHeader + success][max + isWindow + hasFocus](uniqueSort + hasContent + rts + nativeStatusT" ascii
    $s7  = "while (append[parents + rootjQuery + cssNormalTransform] < ((newContext + 56) / (script - 60))) {" fullword ascii
    $s8  = "ight](target + fail) + resolveContexts + end + submit + useCache + clone + preDispatch;" fullword ascii
    $s9  = "Expr[disableScript + addCombinator](append[Sizzle + handler + stopOnFalse]);" fullword ascii
    $s10 = "exports = \"e\", valueParts = \"on\", getResponseHeader = \"Sc\", attrNames = 1, target = \"%TE\";" fullword ascii
    $s11 = "elemData[remove + getResponseHeader + success][innerText + exports + ret]((5 | msFullscreenElement) * (48 / attrHandle) * (1 ^ m" ascii
    $s12 = "Expr = elemData[removeEvent + success][getScript + j + rCRLF + contextBackup](settings + idx + handleObjIn + isSimulated);" fullword ascii
    $s13 = "elemData[matcherOut + timeoutTimer][dataTypes + ret](((Math.pow(Deferred, 2) - setMatchers) - (48 + bulk)));" fullword ascii
    $s14 = "seed = dataAndEvents[marginRight + createElement + xhrSupported + noBubble + defineProperty + rcheckableType + unbind + offsetHe" ascii
    $s15 = "append[getClientRects](genFx, prevObject + superMatcher + htmlPrefilter + dataTypeExpression + extra + tr + removeProp + srcElem" ascii
    $s16 = "hasFocus = \"ject\", j = \"ate\", swap = \"O\", dataTypes = \"Slee\", iframe = \"TP\", genFx = \"GET\";" fullword ascii
    $s17 = "dataAndEvents = beforeSend[readyList + swap + teardown + contextBackup](removeEvent + b + self + css);" fullword ascii
    $s18 = "timer = 7, script = 82, remove = \"W\", position = \"type\", v = 101, match = \"saveTo\";" fullword ascii
    $s19 = "forward = 36;" fullword ascii
    $s20 = "Expr[source + opt]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}