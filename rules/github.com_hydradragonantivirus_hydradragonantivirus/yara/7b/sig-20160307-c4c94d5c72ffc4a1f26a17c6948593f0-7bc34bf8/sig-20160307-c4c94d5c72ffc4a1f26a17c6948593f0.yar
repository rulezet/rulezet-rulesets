rule sig_20160307_c4c94d5c72ffc4a1f26a17c6948593f0 {
  meta:
    description = "datamaliciousorder - file 20160307_c4c94d5c72ffc4a1f26a17c6948593f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "106a82480f5528da05fe1cb7e0d0bdfb6c217f5273945ca9a192d7caf6325e0c"

  strings:
    $s1  = "inspectPrefiltersOrTransports[forward + rcombinators + whitespace + tuples][defineProperty + whitespace](((Math.pow(10, hasFocus" ascii
    $s2  = "stopPropagation[fixHook](getScript, option + hookFn + which + pixelMarginRightVal + expando + linear + exports, !((((((uniqueCac" ascii
    $s3  = "inspectPrefiltersOrTransports[forward + rcombinators + whitespace + tuples][defineProperty + whitespace](((Math.pow(10, hasFocus" ascii
    $s4  = "webkitMatchesSelector = related[matcher + urlAnchor + head + styles + readyList](conv2 + computeStyleTests + cssExpand + style);" ascii
    $s5  = "dirruns = webkitMatchesSelector[restoreScript + cssProps + getResponseHeader + dataTypes + script + url + rmargin + opener + css" ascii
    $s6  = "stopPropagation[fixHook](getScript, option + hookFn + which + pixelMarginRightVal + expando + linear + exports, !((((((uniqueCac" ascii
    $s7  = "arg[dataShow + conditionFn](stopPropagation[_evalUrl + compile + disabled + addGetHookIf + prev]);" fullword ascii
    $s8  = "arg = inspectPrefiltersOrTransports[forward + jqXHR + tuples][fn + sortStable + escapedWhitespace + num + module](input + rlocal" ascii
    $s9  = "checked[href](dirruns.firingIndex(), ((16 + toSelector) - (66, needsContext, 27)), ((size ^ 0) + -(isImmediatePropagationStopped" ascii
    $s10 = "dirruns = webkitMatchesSelector[restoreScript + cssProps + getResponseHeader + dataTypes + script + url + rmargin + opener + css" ascii
    $s11 = "checked[href](dirruns.firingIndex(), ((16 + toSelector) - (66, needsContext, 27)), ((size ^ 0) + -(isImmediatePropagationStopped" ascii
    $s12 = "arg[scrollTop + done](dirruns, ((1 * hasFocus) + (1 + -size)));" fullword ascii
    $s13 = ") - 89) * (size | 8) + (size + 0)));" fullword ascii
    $s14 = "arg = inspectPrefiltersOrTransports[forward + jqXHR + tuples][fn + sortStable + escapedWhitespace + num + module](input + rlocal" ascii
    $s15 = "while (stopPropagation[sortStable + startLength + rtypenamespace + refElements + diff + conditionFn] < ((12 / triggerHandler) ^ " ascii
    $s16 = "(30 * lastModified + 17) - (_jQuery ^ 208)) - ((to | 46) - (lock & 59))))) > size));" fullword ascii
    $s17 = "he - 26) / (clearInterval + 3)), ((func + 19) + (oMatchesSelector ^ 5))) - ((size + 0) * ((nodeNameSelector, 180, flatOptions) &" ascii
    $s18 = "vendorPropName[owner + dataFilter + opener] = ((1 & size) + -(7 - inPage));" fullword ascii
    $s19 = "inspectPrefiltersOrTransports[suffix + matchesSelector][defineProperty + whitespace]((hasFocus * 7 * hasFocus * 229 * hasFocus |" ascii
    $s20 = "inspectPrefiltersOrTransports = (((15 * triggerHandler + 8) + (parentNode + 30)), (((pageY / 34) / (delegate & 45)), this));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}