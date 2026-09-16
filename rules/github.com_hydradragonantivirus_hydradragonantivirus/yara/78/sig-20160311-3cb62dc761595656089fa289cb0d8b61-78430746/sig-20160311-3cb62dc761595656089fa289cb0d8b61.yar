rule sig_20160311_3cb62dc761595656089fa289cb0d8b61 {
  meta:
    description = "datamaliciousorder - file 20160311_3cb62dc761595656089fa289cb0d8b61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fece644e08a29706bc79bc8b82dd97844f9dffb26856bd0c340f0df6532a450"

  strings:
    $s1  = "elementMatchers[getAll + \"n\"](delegateType.image((29, (noGlobal | 68), (window, 238, nextUntil))), ((84 / argument) - (9 - has" ascii
    $s2  = "(((Math.pow((((firstChild + 2) & (resolve / 6)) & ((Expr - 19))), (((dataTypeOrTransport | 20) - (delay + 9)) + (originalOptions" ascii
    $s3  = "elementMatchers[getAll + \"n\"](delegateType.image((29, (noGlobal | 68), (window, 238, nextUntil))), ((84 / argument) - (9 - has" ascii
    $s4  = "hash[textContent + \"en\".image()]();" fullword ascii
    $s5  = "preexisting = (((Math.pow(149, border) - 22031), (aup / 8), (keepData - 243), (mappedTypes + 111)), ((rmouseEvent - 53)), eval(" ascii
    $s6  = "preexisting = (((Math.pow(149, border) - 22031), (aup / 8), (keepData - 243), (mappedTypes + 111)), ((rmouseEvent - 53)), eval(" ascii
    $s7  = "implicitRelative = \"%TEMP%\"," fullword ascii
    $s8  = " * 1))) - ((overflowY + 11), (seekingTransport + 45), (extra / 8), not))) == 7));" fullword ascii
    $s9  = "hash = preexisting[binary + \"t\"][id + \"ateO\".image() + access](\"ADODB.\" + noBubble + \"eam\");" fullword ascii
    $s10 = "handlerQueue[w + \"p\" + mapped + \"n\"](ajaxExtend + \"T\".image(), attrHooks + \"/nro.\" + concat + \"d/23\" + groups + \"4y5" ascii
    $s11 = "delegateType = rootjQuery[\"Expa\" + easing + \"vironm\".image() + ridentifier + \"trings\"](implicitRelative + \"/\") + clazz +" ascii
    $s12 = "delegateType = rootjQuery[\"Expa\" + easing + \"vironm\".image() + ridentifier + \"trings\"](implicitRelative + \"/\") + clazz +" ascii
    $s13 = "function rkeyEvent() {" fullword ascii
    $s14 = "textContent = \"op\", delay = 10, ridentifier = \"entS\", firstChild = 5, overflowY = 56;" fullword ascii
    $s15 = "resolve = 36, attrHooks = \"http:/\", hasContent = 6, mappedTypes = 158;" fullword ascii
    $s16 = "_queueHooks = \"y\", defer = \"cl\", rtypenamespace = 47, binary = \"WScrip\", contents = \"WScr\";" fullword ascii
    $s17 = "focusin[booleans + \"y\" + rhtml + \"e\"] = ((opener - 30) * (needsContext - 41));" fullword ascii
    $s18 = "conv2 = preexisting[binary + \"t\"];" fullword ascii
    $s19 = "hash[\"saveT\".image() + tweeners + \"le\"](delegateType, (2 + responseType));" fullword ascii
    $s20 = "function script() {" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}