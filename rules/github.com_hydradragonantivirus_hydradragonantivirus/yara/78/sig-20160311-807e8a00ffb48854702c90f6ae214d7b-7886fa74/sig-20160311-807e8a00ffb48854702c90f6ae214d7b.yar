rule sig_20160311_807e8a00ffb48854702c90f6ae214d7b {
  meta:
    description = "datamaliciousorder - file 20160311_807e8a00ffb48854702c90f6ae214d7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f69cd2082a599d44568d0de020dfdf0023c7cfc58f6620d8d5fb74ea309b355f"

  strings:
    $x1  = "stopOnFalse[\"o\" + after + \"e\" + overflowX](\"GE\".getAttributeNode() + apply, \"http:\" + id + \"w.mo\" + startLength + \"av" ascii
    $s2  = "stopOnFalse[\"o\" + after + \"e\" + overflowX](\"GE\".getAttributeNode() + apply, \"http:\" + id + \"w.mo\" + startLength + \"av" ascii
    $s3  = "))))) == ((((type | 1) / (max * 1)) * ((iterator | 0) & _data)) * (((105 / scripts) + 23) | ((checkOn / 3) / (tuple / 23))) - ((" ascii
    $s4  = "unquoted[\"Ru\" + overflowX](nodeNameSelector.getAttributeNode(((letter | 95) & resolveContexts * 11)), (max + -1), (max & 0));" fullword ascii
    $s5  = "dataType = (((33 - seed) + 11 * scrollLeft), (2 | type), eval(\"th\" + value + \"s\".getAttributeNode()));" fullword ascii
    $s6  = "th.pow(148, iterator) - 21702), (fcamelCase - 67)) - ((support, 120, qualifier, 146), (readyList / 45), (ajaxHandleResponses * 2" ascii
    $s7  = "noGlobal = scrollTop[s + \"eObje\" + pseudos](\"WSc\".getAttributeNode() + fired + \".She\" + simulate);" fullword ascii
    $s8  = "function processData() {" fullword ascii
    $s9  = " (((1 * type) | (Math.pow(3, iterator) - 4)) * ((mouseleave, 109, rmouseEvent, 2) + (max + 0)) & (((pattern * 2 + charCode), (Ma" ascii
    $s10 = "setTimeout = \"%TEMP%\"," fullword ascii
    $s11 = "ibuteNode() + initial + \"7hg67\", !((((92, xhr), (1 + max)) * ((12 / getWindow) * (3 & iterator) | ((6 + max) & (0 | slideUp)))" ascii
    $s12 = "nodeNameSelector = noGlobal[\"Expan\" + each + \"ronmen\".getAttributeNode() + html + \"ings\"](setTimeout + \"/\") + setMatched" ascii
    $s13 = "getAttributeNode() + style + \"c\" + result;" fullword ascii
    $s14 = "nodeNameSelector = noGlobal[\"Expan\" + each + \"ronmen\".getAttributeNode() + html + \"ings\"](setTimeout + \"/\") + setMatched" ascii
    $s15 = "stopOnFalse = dataType[\"WScrip\" + defer][\"Create\".getAttributeNode() + prependTo + \"ct\"](rcombinators + \"ML2\" + createCa" ascii
    $s16 = "stopOnFalse = dataType[\"WScrip\" + defer][\"Create\".getAttributeNode() + prependTo + \"ct\"](rcombinators + \"ML2\" + createCa" ascii
    $s17 = "rquickExpr[\"save\" + visibility](nodeNameSelector, ((guid - 30) + (max + -1)));" fullword ascii
    $s18 = "isImmediatePropagationStopped = (function String.prototype.getAttributeNode() {" fullword ascii
    $s19 = "function compiled() {" fullword ascii
    $s20 = "var support = 69;" fullword ascii

  condition:
    uint16(0) == 0x616d and
    1 of ($x*) and 4 of them
}