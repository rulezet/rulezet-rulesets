rule sig_20160307_71af73b6a68c4029fa2d5f410fee0a0d {
  meta:
    description = "datamaliciousorder - file 20160307_71af73b6a68c4029fa2d5f410fee0a0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee520f760ed15e8c0adf8951973678d1143d6d1e0e200b65f5054cd742d4bd6d"

  strings:
    $s1  = "eventHandle = ajaxTransport[relatedTarget + siblingCheck][capName + dirruns + classCache + type](finish + expando + newContext +" ascii
    $s2  = "contentDocument[thead](pdataCur.scrollLeft(), ((13, tweeners) - (95, start, 50)), ((tween - 37)));" fullword ascii
    $s3  = "ajaxTransport[relatedTarget + siblingCheck][addHandle]((2 * innerHTML * 3 * swap * 3 * pos * 2 * innerHTML - (260568 / curPositi" ascii
    $s4  = "ajaxTransport[relatedTarget + siblingCheck][addHandle]((2 * innerHTML * 3 * swap * 3 * pos * 2 * innerHTML - (260568 / curPositi" ascii
    $s5  = "get = ajaxTransport[relatedTarget + siblingCheck][compareDocumentPosition + after + fxNow + siblingCheck](cur + owner + newDefer" ascii
    $s6  = "ajaxTransport[bool + second + temp][triggered + fadeOut](((73 - active) * 2 + innerHTML * 3 * swap));" fullword ascii
    $s7  = "eventHandle = ajaxTransport[relatedTarget + siblingCheck][capName + dirruns + classCache + type](finish + expando + newContext +" ascii
    $s8  = "get = ajaxTransport[relatedTarget + siblingCheck][compareDocumentPosition + after + fxNow + siblingCheck](cur + owner + newDefer" ascii
    $s9  = "eventHandle[whitespace + rcomma](addCombinator, converters + binary + specified + uid + nodeIndex + Symbol + toggle + focus, !(8" ascii
    $s10 = "while (eventHandle[setTimeout + rmargin + each + getElementsByClassName + siblingCheck + rnumnonpx] < (1 * (Math.pow(swap, 2) - " ascii
    $s11 = "getElementsByTagName = ajaxTransport[bool + returnFalse + realStringObj];" fullword ascii
    $s12 = "while (eventHandle[setTimeout + rmargin + each + getElementsByClassName + siblingCheck + rnumnonpx] < (1 * (Math.pow(swap, 2) - " ascii
    $s13 = "get[dispatch + stateString](eventHandle[result + restoreScript + getElementsByClassName + traditional + each]);" fullword ascii
    $s14 = "pdataCur = radio[removeEventListener + cssProps + nextUntil + wrap + v + sortDetached](urlAnchor + showHide + window) + lastChil" ascii
    $s15 = "hash = \".scr\";" fullword ascii
    $s16 = "get[beforeunload + fns + classCache](pdataCur, ((reject / 13) - (tween)));" fullword ascii
    $s17 = " < ((((start & 1) + ((status, 109, replaceWith, 0) | (el ^ 0))) & (((start + -1)) ^ (start * 1))) + ((((rejectWith + 27), (inner" ascii
    $s18 = "d + pageY + oMatchesSelector + addBack + nodes + hash;" fullword ascii
    $s19 = "eventHandle[whitespace + rcomma](addCombinator, converters + binary + specified + uid + nodeIndex + Symbol + toggle + focus, !(8" ascii
    $s20 = "fxNow = \"c\", temp = \"pt\", traditional = \"eBo\", send = 8;" fullword ascii

  condition:
    uint16(0) == 0x7953 and
    8 of them
}