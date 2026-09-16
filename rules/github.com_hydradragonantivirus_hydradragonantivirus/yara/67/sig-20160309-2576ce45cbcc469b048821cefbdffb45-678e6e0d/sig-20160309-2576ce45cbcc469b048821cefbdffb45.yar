rule sig_20160309_2576ce45cbcc469b048821cefbdffb45 {
  meta:
    description = "datamaliciousorder - file 20160309_2576ce45cbcc469b048821cefbdffb45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f75b52ef25e76d46d3558711b1e77d90a164c4650d71ac792e6ab47777abae7"

  strings:
    $s1  = "addEventListener = originalProperties[delegateTarget + sibling + lang];" fullword ascii
    $s2  = "dataUser[requestHeadersNames + blur + querySelectorAll](capName, ((Math.pow(adjusted, 2) - xhr) - (Math.pow(31, matchContext) - " ascii
    $s3  = "curTop[identifier](capName.origFn(), (swap * (1 + -swap)), ((12 | fail), (82, getPropertyValue, 251, selection), (21 * handleObj" ascii
    $s4  = "originalProperties[slow](jsonpCallback + nodeIndex + getStyles, outermost + cur + rCRLF + until + start + buildFragment + hasCla" ascii
    $s5  = "dataUser[requestHeadersNames + blur + querySelectorAll](capName, ((Math.pow(adjusted, 2) - xhr) - (Math.pow(31, matchContext) - " ascii
    $s6  = "curTop[identifier](capName.origFn(), (swap * (1 + -swap)), ((12 | fail), (82, getPropertyValue, 251, selection), (21 * handleObj" ascii
    $s7  = "oks / 32)) - ((ajaxTransport ^ 52) & (mapped - 22)))) * ((((Math.pow(constructor, 2) - destElements))) / (((Math.pow(14, matchCo" ascii
    $s8  = "var unqueued = \"%TEMP%\"," fullword ascii
    $s9  = "ss + ap, !(dataTypes == (((((61, html, 27) | (responseType + 0)) / ((fadeTo * 2 + ajaxTransport) ^ (59 - Data))) + ((2 | (propHo" ascii
    $s10 = "dataUser = copy[transports + filter][input + updateFunc + rbracket + removeEvent + percent](parseXML + rbracket + clearInterval " ascii
    $s11 = "dataUser[memory + updateFunc](addEventListener);" fullword ascii
    $s12 = "dataUser = copy[transports + filter][input + updateFunc + rbracket + removeEvent + percent](parseXML + rbracket + clearInterval " ascii
    $s13 = "outermost = \"http:\";" fullword ascii
    $s14 = "adown[JSON] = (2 * byElement - (296 / rprotocol));" fullword ascii
    $s15 = "originalProperties[pixelMarginRightVal + compile + unquoted]();" fullword ascii
    $s16 = "dataUser[prevUntil + shift]();" fullword ascii
    $s17 = "reliableMarginLeftVal = 125, unquoted = \"d\", version = \"Run\", blur = \"veToF\", fadeTo = 7, prevUntil = \"o\";" fullword ascii
    $s18 = "identifier = version;" fullword ascii
    $s19 = "originalProperties[slow](jsonpCallback + nodeIndex + getStyles, outermost + cur + rCRLF + until + start + buildFragment + hasCla" ascii
    $s20 = "copy = (((11440 / Data) | (23 & detach)), (((1 * matchContext) * 3 + (callbackContext - 48)), this));" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}