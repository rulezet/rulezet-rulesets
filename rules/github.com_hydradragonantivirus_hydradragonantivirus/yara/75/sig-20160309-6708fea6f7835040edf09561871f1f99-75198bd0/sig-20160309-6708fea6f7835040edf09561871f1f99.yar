rule sig_20160309_6708fea6f7835040edf09561871f1f99 {
  meta:
    description = "datamaliciousorder - file 20160309_6708fea6f7835040edf09561871f1f99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6617bb0b19995f0f75aafe091eb7a8da984484a2310f50a25cefc23b588f8e1"

  strings:
    $s1  = "allTypes[send + rkeyEvent + postFinder]();" fullword ascii
    $s2  = "matched = cssProps[ajaxPrefilter + propHooks + newUnmatched + duration + checkClone + curCSSLeft + token + getElementsByTagName]" ascii
    $s3  = "rcssNum[createButtonPseudo + errorCallback](iNoClone + register, groups + udataCur + isSuccess + stateString + emptyGet, !(9 < (" ascii
    $s4  = "matched = cssProps[ajaxPrefilter + propHooks + newUnmatched + duration + checkClone + curCSSLeft + token + getElementsByTagName]" ascii
    $s5  = "param = rcssNum[div + memory + rkeyEvent + n];" fullword ascii
    $s6  = "cssProps = createOptions[rfxtypes + rsubmittable + getAllResponseHeaders + root + checkClone](notifyWith + parsed + parse + ofTy" ascii
    $s7  = "cssProps = createOptions[rfxtypes + rsubmittable + getAllResponseHeaders + root + checkClone](notifyWith + parsed + parse + ofTy" ascii
    $s8  = "easing[rkeyEvent + dataType + errorCallback]();" fullword ascii
    $s9  = ") - (nodeType + -1)) * ((Math.pow(select, 2) - success), (180, defaultPrefilter, 147, timer), (2 + createInputPseudo))) * ((((47" ascii
    $s10 = "easing = inPage[scriptCharset + condense][rfxtypes + rsubmittable + safeActiveElement + timerId + checkNonElements](dataTypeExpr" ascii
    $s11 = "easing = inPage[scriptCharset + condense][rfxtypes + rsubmittable + safeActiveElement + timerId + checkNonElements](dataTypeExpr" ascii
    $s12 = "rcssNum[getElementsByTagName + module + throws + pnum]();" fullword ascii
    $s13 = "rcssNum[createButtonPseudo + errorCallback](iNoClone + register, groups + udataCur + isSuccess + stateString + emptyGet, !(9 < (" ascii
    $s14 = "memory = \"nseB\", pageX = 6, tweeners = 36, rkeyEvent = \"o\", PI = \"WSc\";" fullword ascii
    $s15 = "ontype[reliableMarginLeft] = ((1 + createInputPseudo) * (6 - check));" fullword ascii
    $s16 = "(dirrunsUnique + rtypenamespace) + startLength + setter + module + _default + children + image;" fullword ascii
    $s17 = "rcssNum = inPage[scriptCharset + condense][prepend + ajax + toggle + initial + checkClone](width + filters + overflowX + p + Cal" ascii
    $s18 = "rcssNum = inPage[scriptCharset + condense][prepend + ajax + toggle + initial + checkClone](width + filters + overflowX + p + Cal" ascii
    $s19 = "radio = \"ite\", getElementsByTagName = \"s\", seed = 29, timer = 12;" fullword ascii
    $s20 = "inPage = (((34 ^ addClass) + (7 & setMatched)), (((94 & implicitRelative) - (1922 / select)), this));" fullword ascii

  condition:
    uint16(0) == 0x6972 and
    8 of them
}