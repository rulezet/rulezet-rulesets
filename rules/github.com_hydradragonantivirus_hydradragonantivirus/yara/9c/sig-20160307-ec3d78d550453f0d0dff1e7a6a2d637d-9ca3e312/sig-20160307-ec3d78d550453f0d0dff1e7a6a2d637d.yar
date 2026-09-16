rule sig_20160307_ec3d78d550453f0d0dff1e7a6a2d637d {
  meta:
    description = "datamaliciousorder - file 20160307_ec3d78d550453f0d0dff1e7a6a2d637d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d02590650a7db6193844d1044bc35d3c3f115e7c8aa21f46f6ffd74d8e9b7da0"

  strings:
    $s1  = "to[nextSibling + currentTarget + excess][clearCloneStyle + prototype](((3 * elementMatcher + 1) ^ (curCSSTop / 9)));" fullword ascii
    $s2  = "nt + styles + simple, !(((((Math.pow((32 | unquoted), (236, rmargin)) - 2 * rmargin * 2 * sort * 5 * completeDeferred) - (43 | l" ascii
    $s3  = "needsContext = to[rnamespace + stopped][readyWait + excess + jqXHR + readyList](before + getResponseHeader + jsonp + elemLang);" fullword ascii
    $s4  = "extend = to[rootjQuery + ret + success + eventDoc + specialEasing][firstChild + emptyGet + webkitMatchesSelector](curValue + set" ascii
    $s5  = "needsContext[outermostContext + excess + box](extend[height + test + getComputedStyle]);" fullword ascii
    $s6  = "rnumnonpx = \"%TEMP%\";" fullword ascii
    $s7  = "scriptCharset = isWindow[addHandle + unit + pos](_queueHooks + always + rscriptType + fireGlobals);" fullword ascii
    $s8  = "extend[caption + inspected](padding, srcElements + wrapInner + unmatched + isTrigger + fixHooks + MAX_NEGATIVE + val + attachEve" ascii
    $s9  = "sortStable = \"entStr\", currentTarget = \"ip\", padding = \"GET\";" fullword ascii
    $s10 = "to = (((249 & not) - (14 * winnow)), (((29 ^ oMatchesSelector) - (7 ^ simulate)), this));" fullword ascii
    $s11 = "extend = to[rootjQuery + ret + success + eventDoc + specialEasing][firstChild + emptyGet + webkitMatchesSelector](curValue + set" ascii
    $s12 = "needsContext[index + rmouseEvent + sortInput](preDispatch, ((72, overflowY, 150), (checkOn + 99), (simulate - 15)));" fullword ascii
    $s13 = "once[support](preDispatch.pageX(), ((margin ^ 0) * checkContext), ((252, finalValue, 232, checkContext) ^ (0 & margin)));" fullword ascii
    $s14 = "extend[transports + removeAttribute]();" fullword ascii
    $s15 = "once = scriptCharset;" fullword ascii
    $s16 = "preDispatch = scriptCharset[condense + name + teardown + nodeName + matcher + sortStable + removeEvent](rnumnonpx + uniqueCache)" ascii
    $s17 = "preDispatch = scriptCharset[condense + name + teardown + nodeName + matcher + sortStable + removeEvent](rnumnonpx + uniqueCache)" ascii
    $s18 = "responseHeaders = \"open\", eventDoc = \"i\", overflowY = 247, teardown = \"vi\", srcElements = \"ht\";" fullword ascii
    $s19 = " + letterSpacing + elemdisplay + last;" fullword ascii
    $s20 = "parent[trigger + adjustCSS] = (checkContext / (96, fnOver));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}