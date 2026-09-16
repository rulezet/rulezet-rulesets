rule sig_20160307_acdfb096bb00164d95c81374e832b2c9 {
  meta:
    description = "datamaliciousorder - file 20160307_acdfb096bb00164d95c81374e832b2c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60686f3f20ffc3e7e04aebbf7c0a8e7875a4f90268703916012e774610d91a90"

  strings:
    $s1  = "compareDocumentPosition[location + copyIsArray](scrollTop, rsingleTag + boxSizingReliableVal + rescape + detectDuplicates + toke" ascii
    $s2  = " ((3 * onabort + 1) / (rrun ^ 5)) * (((get ^ 38) & (detach | 101)) / (Math.pow((rfocusable | 0), (rrun | 2)) - (checkClone - 252" ascii
    $s3  = "pect) * (56 - always) * 2 * (Math.pow(onabort, 2) - getWidthOrHeight) * (3 ^ rrun));" fullword ascii
    $s4  = "compiled[relative + rnumnonpx][view + els](2 * (trigger & 5) * (Math.pow(getWidthOrHeight, 2) - delegateCount) * (2 & callbackEx" ascii
    $s5  = "addClass[rprotocol + cssProps + writable](combinator, ((256 / pipe) / (97, hasContent, 135, getWidthOrHeight)));" fullword ascii
    $s6  = "compiled[relative + rnumnonpx][view + els](2 * (trigger & 5) * (Math.pow(getWidthOrHeight, 2) - delegateCount) * (2 & callbackEx" ascii
    $s7  = "stopped[setFilters](combinator.globalEventContext(), (0 & (first * 1)), ((fontWeight - 38) * (rrun ^ 0)));" fullword ascii
    $s8  = "compiled[relative + isSuccess + find][script + siblings](((id, 127, reliableMarginLeftVal, 108) & (dataTypeExpression, 117, asse" ascii
    $s9  = "nCache + show + cache + pos + curOffset, !(9 < ((Math.pow((((attrHooks | 18) ^ (rrun | 6)) - (Math.pow(compile, (32 / fns)) - (1" ascii
    $s10 = "outermost = \"ct\", host = \".sc\", getter = \"tion\", globalEval = \"ate\", rsingleTag = \"http\";" fullword ascii
    $s11 = "))) * (((first * 1) * onabort) | ((10 - getWindow) + (44 / optSelected))))));" fullword ascii
    $s12 = "compiled[relative + isSuccess + find][script + siblings](((id, 127, reliableMarginLeftVal, 108) & (dataTypeExpression, 117, asse" ascii
    $s13 = "compiled = (((47, xhrSuccessStatus, 90, pseudo) + 7 * onabort), (((66 - deepDataAndEvents), (153 ^ optall), (1702 / settings), (" ascii
    $s14 = "89 ^ matchedCount))), (((105 ^ username), (11 + unit), 2 * compile) / ((2162 / settings) - 2 * callbackExpect * 2 * callbackExpe" ascii
    $s15 = "isXML[visibility + divStyle + getter] = (0 / needsContext);" fullword ascii
    $s16 = "combinator = optgroup[xhrFields + attrHandle + rquickExpr + concat + inArray + origFn + r20 + preFilter](doneName + hasCompare) " ascii
    $s17 = "* (nodeType - 20) * (callbackContext / 8) * (callbackExpect & 2) * (first * 2) | ((rmsPrefix * 6 + parent) - (462 - clientY))))," ascii
    $s18 = "optgroup = rsubmitterTypes[finish + err + owner + teardown + complete](hide + rdashAlpha + close);" fullword ascii
    $s19 = "slow[options + writable] = (1 ^ rrun);" fullword ascii
    $s20 = "compareDocumentPosition = compiled[relative + rnumnonpx][finish + htmlPrefilter + _evalUrl + outermost](origName + module + ajax" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}