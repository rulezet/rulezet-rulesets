rule sig_20160307_23c461e05edfd43375f4fc59a9aa9574 {
  meta:
    description = "datamaliciousorder - file 20160307_23c461e05edfd43375f4fc59a9aa9574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00801022acd2d97815757dc5d6fc2b8af4f86dea5a29ee58508e5a8a61d4f10a"

  strings:
    $s1  = "count[traditional](high, cssHooks + match + holdReady + prevObject + div1 + checkClone, !((Math.pow(((((_queueHooks ^ 2) + (fini" ascii
    $s2  = "    chainable[clientTop + dataTypes + readyWait][postMap + stored]((Math.pow(boxSizingReliable * 13, rbracket) - (8181 & timer))" ascii
    $s3  = "    chainable[clientTop + dataTypes + readyWait][postMap + stored]((Math.pow(boxSizingReliable * 13, rbracket) - (8181 & timer))" ascii
    $s4  = "while(count[keyHooks + indirect + addCombinator + dirruns] < (64 / dataTypeOrTransport) * 2) {" fullword ascii
    $s5  = "chainable = ((Math.pow((187 & setGlobalEval), 2) - (matchers, 200, onabort, 34408)), (((addHandle - 28) + (fast, 3)), this));" fullword ascii
    $s6  = "rescape = PI[setRequestHeader + iNoClone + keyCode + responseContainer + ajax](Sizzle + unmatched) + clearQueue + values + dataU" ascii
    $s7  = "count[traditional](high, cssHooks + match + holdReady + prevObject + div1 + checkClone, !((Math.pow(((((_queueHooks ^ 2) + (fini" ascii
    $s8  = "rescape = PI[setRequestHeader + iNoClone + keyCode + responseContainer + ajax](Sizzle + unmatched) + clearQueue + values + dataU" ascii
    $s9  = "chainable[trim + calculatePosition + readyWait][postMap + stored](((42508 * rbracket + 4984) / (clone + 0)));" fullword ascii
    $s10 = "count = chainable[timeStamp + end][hasCompare + i + uniqueID + webkitMatchesSelector](initialInUnit + bulk + selectors + bup);" fullword ascii
    $s11 = "Sizzle = \"%TEMP\";" fullword ascii
    $s12 = "dataUser = \"er\", dataTypeOrTransport = 32, trim = \"WS\", beforeunload = \"oF\";" fullword ascii
    $s13 = "i = \"reateO\", timeStamp = \"WScr\", traditional = \"open\", divStyle = \"B.\", high = \"GET\";" fullword ascii
    $s14 = "serialize = \"posi\", responseHeadersString = \"Cre\", conditionFn = \"ript\", postMap = \"Sle\", setRequestHeader = \"Expan\";" fullword ascii
    $s15 = "PI = isSimulated[responseHeadersString + addBack + beforeSend + preFilter](href + hooks + cacheLength);" fullword ascii
    $s16 = "reject = chainable[clientTop + conditionFn][setTimeout + defaultView + values](nodes + elem + propName + divStyle + eased + srcE" ascii
    $s17 = "reject = chainable[clientTop + conditionFn][setTimeout + defaultView + values](nodes + elem + propName + divStyle + eased + srcE" ascii
    $s18 = "addCombinator = \"dysta\", responseContainer = \"mentSt\", winnow = \"Resp\";" fullword ascii
    $s19 = "when = \"Run\";" fullword ascii
    $s20 = "rjsonp = \"op\", fail = \"onseB\", _queueHooks = 1;" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}