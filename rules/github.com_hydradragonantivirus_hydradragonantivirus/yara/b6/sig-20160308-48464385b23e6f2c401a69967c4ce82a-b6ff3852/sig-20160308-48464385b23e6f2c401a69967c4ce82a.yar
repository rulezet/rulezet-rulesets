rule sig_20160308_48464385b23e6f2c401a69967c4ce82a {
  meta:
    description = "datamaliciousorder - file 20160308_48464385b23e6f2c401a69967c4ce82a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d75f4e531948e969390461805999e4467c8b16a705dbc2b4a2d2867a17075af0"

  strings:
    $s1  = "match = getAll[host + matcherFromGroupMatchers + bindType + e](_load + div1 + delegate);" fullword ascii
    $s2  = "llbackContext) * (2 ^ beforeSend) + (1 * getPropertyValue))), (((Math.pow(192, value) - 36518) / (value & 3)) & ((originalOption" ascii
    $s3  = "Send + 4)), ((jsonProp | 28), (mapped / 37), (Math.pow(responseHeaders, 2) - arg), (Math.pow(204, value) - 41366)), ((getPropert" ascii
    $s4  = "curCSS[finalText + speeds](fadeTo, fire + html + matcherOut + wrapInner + assert + attrNames + view + insertAfter + readyState +" ascii
    $s5  = "while (curCSS[remove + prefilterOrFactory + rcheckableType] < ((Math.pow(mouseenter, 2) - keyHooks) - 30)) {" fullword ascii
    $s6  = "curTop[DOMParser + deep + fnOver + finalText + responseHeadersString] = ((1 + fadeIn) + -(15 - high));" fullword ascii
    $s7  = "fontWeight = stateString[defaultPrefilter + tuples + letterSpacing + e][response + preexisting + _jQuery](trim + rcomma + delega" ascii
    $s8  = " + -1)) + ((fadeIn | 1) | getPropertyValue))) == (Math.pow(((((8 | docElem) / (1 + value)) * ((0 / s) | (1 | concat)) + ((1 + ca" ascii
    $s9  = "((1 * value)) * ((Math.pow(25, value) - 593) / (concat ^ 0)) + (getPropertyValue & 1)) & (((bubbleType / 41) / (xhr + 23)) + ((c" ascii
    $s10 = "optDisabled = \"W\", rfocusable = \"ipt\", checkDisplay = \"%TEMP%\", s = 18, mapped = 2960, inspect = \"S\";" fullword ascii
    $s11 = "* callbackContext)) + (((66 * concat + 55) - callbackContext * 2 * value * 3 * callbackContext), ((Math.pow(79, value) - 6088) &" ascii
    $s12 = "stateString = ((Math.pow((216 & unwrap), 2) - (diff - 6846)), (((checkNonElements - 18) - (fnOut, 34)), this));" fullword ascii
    $s13 = " fix + msMatchesSelector + dirrunsUnique, !(((((Math.pow(genFx, 2) - trigger) - (16 | callbackContext)), ((26 & dataPriv) + (7 *" ascii
    $s14 = "teTarget + cacheURL + list);" fullword ascii
    $s15 = "curCSS = stateString[defaultPrefilter + getAttribute][method + wrapAll + e + rcheckableType + overwritten + _jQuery](show + hasO" ascii
    $s16 = "fire = \"http:\";" fullword ascii
    $s17 = " children + 3)), (value + 0)) * ((getPropertyValue ^ 0) ^ (getPropertyValue * 3)) * (((getPropertyValue & 1) + (getPropertyValue" ascii
    $s18 = "curCSS = stateString[defaultPrefilter + getAttribute][method + wrapAll + e + rcheckableType + overwritten + _jQuery](show + hasO" ascii
    $s19 = "curCSS[finalText + speeds](fadeTo, fire + html + matcherOut + wrapInner + assert + attrNames + view + insertAfter + readyState +" ascii
    $s20 = "yValue * 0) | (Math.pow(valueParts, 2) - createElement)), (7 & beforeSend))), (((2 + (fadeIn ^ 0)) & ((caption ^ 6) - value * 2 " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}