rule sig_20160308_7d9edd827b5fabc060d868383259bfde {
  meta:
    description = "datamaliciousorder - file 20160308_7d9edd827b5fabc060d868383259bfde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1002d5b1a672aa889c4944ad55127bfbcb9870181ac5c7cdc6704f8aeb9db9b"

  strings:
    $s1  = "remove[responseHeaders + insertBefore + hasScripts] = ((cos + -1) & access);" fullword ascii
    $s2  = "timer[postDispatch](animation + optDisabled, removeClass + rbracket + thead + preFilters + resolveWith + bySet + ready, !(((((co" ascii
    $s3  = "dirrunsUnique = (((Math.pow(204, event) - 41376) / (addToPrefiltersOrTransports * 2 + event)), (((72 / replaceWith) ^ (241, matc" ascii
    $s4  = "dirrunsUnique = (((Math.pow(204, event) - 41376) / (addToPrefiltersOrTransports * 2 + event)), (((72 / replaceWith) ^ (241, matc" ascii
    $s5  = "unwrap = dirrunsUnique[checkClone + els][unquoted + animate + proxy](startLength + letterSpacing + gotoEnd + getText);" fullword ascii
    $s6  = " / parentWindow)) | ((39 / sourceIndex) ^ (1 * access))) + (((46 - onreadystatechange) ^ (1 + -cos)) / ((131, combinator, 26, pr" ascii
    $s7  = "tween = rcombinators[test + callbackName + removeData + els](getter + contentType + propFilter + boxSizingReliable + cssText + d" ascii
    $s8  = "tween = rcombinators[test + callbackName + removeData + els](getter + contentType + propFilter + boxSizingReliable + cssText + d" ascii
    $s9  = "dirrunsUnique[attrNames + offset][matchesSelector](((96 ^ onabort) - (68 ^ event)));" fullword ascii
    $s10 = "s) ^ (0 / overwritten)) ^ (((1 * cos) & (1 + -cos)) / ((Math.pow(137, event) - 18621), event * 2 * pageX * 2))) * (((access ^ (0" ascii
    $s11 = "timer = dirrunsUnique[to + propFilter][createButtonPseudo + marginRight + prototype](radioValue + random + run + isXMLDoc + stop" ascii
    $s12 = "unwrap[get + implementation](timer[bubbleType + t + constructor + excess + cleanData]);" fullword ascii
    $s13 = "username = \"e\", run = \"ML2.XM\", time = \".scr\", access = 0, callbackName = \"teO\";" fullword ascii
    $s14 = "opHooks) - (26 ^ uniqueSort))))) == (((1 * access) | (14, cos)) - (0 | access))));" fullword ascii
    $s15 = "timer[postDispatch](animation + optDisabled, removeClass + rbracket + thead + preFilters + resolveWith + bySet + ready, !(((((co" ascii
    $s16 = "finish = tween[prepend + groups + delegateCount + onload + removeEvent + obj](timeStamp + width) + isReady + implementation + ha" ascii
    $s17 = "dirrunsUnique[attrNames + offset][matchesSelector](((1871 + inspect) ^ (14303 & after)));" fullword ascii
    $s18 = "finish = tween[prepend + groups + delegateCount + onload + removeEvent + obj](timeStamp + width) + isReady + implementation + ha" ascii
    $s19 = "timer = dirrunsUnique[to + propFilter][createButtonPseudo + marginRight + prototype](radioValue + random + run + isXMLDoc + stop" ascii
    $s20 = "unwrap[anim + username]();" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}