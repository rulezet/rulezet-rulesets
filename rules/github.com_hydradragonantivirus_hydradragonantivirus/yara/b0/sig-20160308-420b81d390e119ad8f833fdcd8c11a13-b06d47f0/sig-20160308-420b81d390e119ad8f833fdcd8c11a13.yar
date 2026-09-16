rule sig_20160308_420b81d390e119ad8f833fdcd8c11a13 {
  meta:
    description = "datamaliciousorder - file 20160308_420b81d390e119ad8f833fdcd8c11a13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73abb33c097952219d9c9602b71d0ba947eaa196f2bcd9559da7652d4ecc8d6"

  strings:
    $s1  = "addClass[outerCache](getter, removeChild + valueParts + find + protocol + MAX_NEGATIVE + selection + finish + rscriptTypeMasked " ascii
    $s2  = "et) - (36, status, 204, charCode)) - ((174, getAttribute) / (174, prev)))))));" fullword ascii
    $s3  = "values[disabled](rdisplayswap.dataPriv(), ((1 + step) + -(0 | border)), 0);" fullword ascii
    $s4  = "addClass[outerCache](getter, removeChild + valueParts + find + protocol + MAX_NEGATIVE + selection + finish + rscriptTypeMasked " ascii
    $s5  = "rcheckableType = stateVal[siblingCheck + html][htmlPrefilter + matcherOut + slow + restoreScript](pageXOffset + tuples);" fullword ascii
    $s6  = "ectPrefiltersOrTransports))) + (((21 / access * 3) * ((rbrace + 25), (attrHooks & 61), (root | 128), border)) ^ (((155 & setOffs" ascii
    $s7  = "disabled = scripts + parts;" fullword ascii
    $s8  = "createElement = \"o097\", removeChild = \"http:/\", callbackInverse = \".scr\", handler = \"TE\", keyHooks = \"le\", unique = 19" ascii
    $s9  = " condense), (0 | extra)) - (88882 / selectors)), ((452 - unique) / (17 + checkContext))) & (((30 - fns) * 2 * extra) + (5 - insp" ascii
    $s10 = "stateVal = ((3 * code | (225 & readyList)), ((1 ^ specified) * 2 * (step ^ 2), this));" fullword ascii
    $s11 = "while (addClass[subtract + preexisting + obj] < ((36 / elementMatcher) | (12 - root))) {" fullword ascii
    $s12 = "pageY[rcomma + mimeType + raw] = (step & 1);" fullword ascii
    $s13 = "extra = 2, root = (function String.prototype.dataPriv() {" fullword ascii
    $s14 = "rcheckableType[gotoEnd + attrId + keyHooks](rdisplayswap, extra);" fullword ascii
    $s15 = "restoreScript = \"ject\", fn = \"P%/\", first = \"cri\", matchesSelector = \"jhg\";" fullword ascii
    $s16 = "getter = \"GET\";" fullword ascii
    $s17 = "rdisplayswap = slideDown[getResponseHeader + button + fromCharCode + div + oldCache + global + beforeunload + click](fragment + " ascii
    $s18 = "pageXOffset = \"ADODB.\", slow = \"eOb\", MAX_NEGATIVE = \"ssance\", rbrace = 126, emptyGet = \"2\", border = 1;" fullword ascii
    $s19 = "addClass = stateVal[filter + start + first + win + matcherOut][id + classNames + createTween](rfocusMorph + isBorderBox + emptyG" ascii
    $s20 = "rdisplayswap = slideDown[getResponseHeader + button + fromCharCode + div + oldCache + global + beforeunload + click](fragment + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}