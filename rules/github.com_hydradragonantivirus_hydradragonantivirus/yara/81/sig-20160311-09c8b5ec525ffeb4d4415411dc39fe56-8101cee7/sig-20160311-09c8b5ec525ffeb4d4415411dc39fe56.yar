rule sig_20160311_09c8b5ec525ffeb4d4415411dc39fe56 {
  meta:
    description = "datamaliciousorder - file 20160311_09c8b5ec525ffeb4d4415411dc39fe56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c60f44c15a010bc6d6c52d97860d491125dfd08f3c75798552335df983817b35"

  strings:
    $s1  = "unquoted = noBubble[\"Exp\" + superMatcher + \"viro\" + scriptCharset + \"tStrin\".optall() + off](\"%TEMP\" + matchContext) + " ascii
    $s2  = "obj = ((103 * removeAttribute * 3 * getClass / (180, getById, 156, func)), ((0 | globalEventContext) / (5 | temp)), eval(\"th\" " ascii
    $s3  = "unquoted = noBubble[\"Exp\" + superMatcher + \"viro\" + scriptCharset + \"tStrin\".optall() + off](\"%TEMP\" + matchContext) + " ascii
    $s4  = "body[\"Ru\" + hash](unquoted.optall(((57, boxSizingReliable) & (151, host, 91))), ((doneName + 0) + -doneName), ((17 - rparentsp" ascii
    $s5  = "body[\"Ru\" + hash](unquoted.optall(((57, boxSizingReliable) & (151, host, 91))), ((doneName + 0) + -doneName), ((17 - rparentsp" ascii
    $s6  = "detach[\"op\".optall() + removeProp + \"n\"](actualDisplay + \"ET\", origType + \"p:/\".optall() + margin + \".momst\" + wrapAll" ascii
    $s7  = "script) | (7 & rnoInnerhtml)))) + ((((2 * matchesSelector) / (17 + vendorPropName)) + -((20 + doneName) - (0 | nodeName))) | (((" ascii
    $s8  = "obj = ((103 * removeAttribute * 3 * getClass / (180, getById, 156, func)), ((0 | globalEventContext) / (5 | temp)), eval(\"th\" " ascii
    $s9  = "active[addToPrefiltersOrTransports + \"y\" + contentDocument] = ((0 & globalEventContext) | (39 / slow));" fullword ascii
    $s10 = "test = \"osit\", contexts = 17, host = 27, operator = \"is\", before = 173, handlers = \"ript\";" fullword ascii
    $s11 = "detach[unbind + \"e\" + hash + \"d\"]();" fullword ascii
    $s12 = "detach = obj[\"WScrip\" + addToPrefiltersOrTransports][\"Crea\".optall() + readyWait + \"ct\"](iframe + \"2.X\" + opt);" fullword ascii
    $s13 = "+ err + \"g67\".optall(), !(3 == (((((before, 58, getClass) + 2) + (doneName * (1 + -doneName))) - ((1 * removeAttribute) * 2 / " ascii
    $s14 = "requestHeaders[initial + \"eTo\" + append](unquoted, ((1400 / nodeName) / (3 + rxhtmlTag)));" fullword ascii
    $s15 = "10 + prefix), (31 & cssExpand), (194 & t), (4 + vendorPropName)) - ((0 | contexts) - (12 & jQuery)))))));" fullword ascii
    $s16 = "temp = 40;" fullword ascii
    $s17 = "script = 6;" fullword ascii
    $s18 = "active = requestHeaders;" fullword ascii
    $s19 = "simulate = requestHeaders;" fullword ascii
    $s20 = "operator));" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}