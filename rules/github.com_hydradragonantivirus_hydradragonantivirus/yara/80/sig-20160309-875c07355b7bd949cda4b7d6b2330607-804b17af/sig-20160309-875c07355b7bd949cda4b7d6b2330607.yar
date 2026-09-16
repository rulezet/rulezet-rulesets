rule sig_20160309_875c07355b7bd949cda4b7d6b2330607 {
  meta:
    description = "datamaliciousorder - file 20160309_875c07355b7bd949cda4b7d6b2330607.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60262303a0fabe2e7e34050b5afb8f7723bfd460f6cff157610fa7ee6a8aa5fc"

  strings:
    $s1  = "click[toggleClass](qualifier + dataTypes, selectors + inspectPrefiltersOrTransports + matchers + closest + inspectPrefiltersOrTr" ascii
    $s2  = "click = overflow[addCombinator + inspectPrefiltersOrTransports][rnoInnerhtml + size + fixInput + arg + inspectPrefiltersOrTransp" ascii
    $s3  = "overflow[gotoEnd + propHooks + elementMatchers + inspectPrefiltersOrTransports][rheaders](((hasOwn ^ 941919) / readyState));" fullword ascii
    $s4  = "faultPrevented + -1) & (name, 137, seekingTransport, 1))) | ((Math.pow((opt / 36), (setPositiveNumber & 2)) - (linear / 39)) & (" ascii
    $s5  = "css = overflow[getWindow + replaceChild][stateString + noBubble + count + expand](prefix + setGlobalEval + trim + contentDocumen" ascii
    $s6  = "css = overflow[getWindow + replaceChild][stateString + noBubble + count + expand](prefix + setGlobalEval + trim + contentDocumen" ascii
    $s7  = "ansports + setMatched + trim + addGetHookIf + funescape + scriptCharset + specified, !(4 == ((((isDefaultPrevented + 0) & ((isDe" ascii
    $s8  = "_evalUrl = one[extra + results + arg + inspectPrefiltersOrTransports](getWindow + matcherIn + responseText);" fullword ascii
    $s9  = "focusin = \"%TEMP%\";" fullword ascii
    $s10 = "click = overflow[addCombinator + inspectPrefiltersOrTransports][rnoInnerhtml + size + fixInput + arg + inspectPrefiltersOrTransp" ascii
    $s11 = "one = overflow[getWindow + replaceChild];" fullword ascii
    $s12 = "orts](rtagName + getText + button + properties);" fullword ascii
    $s13 = "concat = _evalUrl[prefilterOrFactory + trim + getAttribute + args + fadeIn + setMatchers + doneName + inspectPrefiltersOrTranspo" ascii
    $s14 = "overflow = (59 * (serializeArray / 44) * setPositiveNumber, (((42 - dataFilter) | (26 - fontWeight)), this));" fullword ascii
    $s15 = "setPositiveNumber * 37, (rclass & 127), (inspect - 110), (contexts / 24)))) & (((Math.pow((isDefaultPrevented * 7), (isDefaultPr" ascii
    $s16 = "startTime = \"veToF\", propHooks = \"Scr\", unique = \"ist\", scriptCharset = \"76g4\", arg = \"jec\", defaultPrevented = \"se\"" ascii
    $s17 = "inspectPrefiltersOrTransports = \"t\", linear = 195, trim = \"a\", remaining = \"positi\", list = \"writ\", readyState = 47;" fullword ascii
    $s18 = "pointerleave[textContent + size] = ((1 * classes) ^ (68, isDefaultPrevented));" fullword ascii
    $s19 = "concat = _evalUrl[prefilterOrFactory + trim + getAttribute + args + fadeIn + setMatchers + doneName + inspectPrefiltersOrTranspo" ascii
    $s20 = "evented * 2)) - (shift)) - ((609 - optall) / (47 & _queueHooks))) ^ ((1 + classes) + ((3 & setPositiveNumber) * (102, setPositiv" ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}