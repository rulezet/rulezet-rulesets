rule sig_20160308_13b60b6ea6eb3b0b741aa5a2a1301f27 {
  meta:
    description = "datamaliciousorder - file 20160308_13b60b6ea6eb3b0b741aa5a2a1301f27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ce1d01654afdfdf0221c01e8018cd48ba2c15e61e8571871390ef617bb5e3d2"

  strings:
    $s1  = "pageXOffset[prevUntil + inspectPrefiltersOrTransports](el, _jQuery + expanded + destElements + tmp + contentType + div1 + callba" ascii
    $s2  = "pageXOffset = inspect[hasOwnProperty + postSelector + propFilter + buildParams][needsContext + current + buildParams](bup + wrap" ascii
    $s3  = "inspect[send + rfxtypes][ridentifier + lname](((Math.pow(26, suffix) - 639) ^ (suffix + 63)));" fullword ascii
    $s4  = "6)) * ((timer * 1) ^ (handlerQueue - 4)) + (thead / 47)), ((timer * 2) + (until, 243, define, 1)) * ((open * 2 + resolveWith) / " ascii
    $s5  = "while(pageXOffset[concat + values + emptyStyle + animation] < ((Math.pow(defaultPrefilter, 2) - getJSON) / (172 / resolveWith)))" ascii
    $s6  = "while(pageXOffset[concat + values + emptyStyle + animation] < ((Math.pow(defaultPrefilter, 2) - getJSON) / (172 / resolveWith)))" ascii
    $s7  = "inspect = (((Math.pow(193, suffix) - 37051) | (Math.pow(padding, 2) - progressContexts)), ((Math.pow((1 * handlerQueue), 2) - (d" ascii
    $s8  = "onabort = inspect[send + rfxtypes][dirruns + completed + callbackExpect](window + getElementsByTagName + col);" fullword ascii
    $s9  = "ch + 31)) & (Math.pow((Math.pow(slideDown, 2) - removeEvent), 2) - (parent * 5 + beforeSend))) - (((66 / id)) ^ ((31 & results) " ascii
    $s10 = "inspect = (((Math.pow(193, suffix) - 37051) | (Math.pow(padding, 2) - progressContexts)), ((Math.pow((1 * handlerQueue), 2) - (d" ascii
    $s11 = "pageXOffset[prevUntil + inspectPrefiltersOrTransports](el, _jQuery + expanded + destElements + tmp + contentType + div1 + callba" ascii
    $s12 = " * caption | 2 * tick * 3 * suffix * 2 * suffix), ((38 | global) & (Math.pow(39, suffix) - 1467))))) == (((((binary / 50) + (whi" ascii
    $s13 = "pageXOffset = inspect[hasOwnProperty + postSelector + propFilter + buildParams][needsContext + current + buildParams](bup + wrap" ascii
    $s14 = "(((34 / setDocument) * (1 + timer)) & (1 ^ (eventPath | 2))) ^ ((rxhtmlTag, 1) + -(jQuery, 1)))) - (((suffix * 2 * locked - (3 *" ascii
    $s15 = " 1))), (((tick & 3) & (tick ^ 0)) & ((focus - 248), suffix))) - (((12 & handlerQueue) + (3 ^ allTypes)) & ((47 - fireWith)))), (" ascii
    $s16 = "insertBefore[chainable](msFullscreenElement.animated(), ((1 * eventPath) ^ (0 | eventPath)), ((1 * timer) * (33 - jQuery)));" fullword ascii
    $s17 = "originalEvent[buildParams + isTrigger] = ((timer + 0) + (timer + -1));" fullword ascii
    $s18 = "(3 + currentValue)) * ((28 + tick) & (4 + nid)), ((183, matcherFromTokens, 0) ^ (timer + 4))))));" fullword ascii
    $s19 = "ckName + defaultExtra + pos + finalValue, !((Math.pow((Math.pow(((timer * 0) ^ ((timer + 1) * (cloneCopyEvent, 2) + (eventPath ^" ascii
    $s20 = "_evalUrl = \"TEMP%\";" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}