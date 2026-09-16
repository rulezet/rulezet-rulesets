rule sig_20160311_93ff01f1be29dfd0dcbf395bef361e64 {
  meta:
    description = "datamaliciousorder - file 20160311_93ff01f1be29dfd0dcbf395bef361e64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3bd748490e504ec97788bf609f948c39c46f47af8a076b7b91c69e2296351c3"

  strings:
    $s1  = " \"blik\" + ajaxTransport + \"8h86\" + matchAnyContext, !(eventDoc == ((((Math.pow(47, handle) - 2161) / (always + 20)) * (hasOw" ascii
    $s2  = "owner[resolveContexts + \"p\" + css + \"n\"](last + \"E\".elem() + box, \"http\" + camelCase + \"rfu\" + classes + \"lice.\".ele" ascii
    $s3  = "rfxtypes = (((1450 / removeEventListener) * (1 * handle) + (5 * camel + 2)), ((multipleContexts / 43) | (rcomma - 37)), eval(\"t" ascii
    $s4  = "fireGlobals = contents[callbackInverse + \"eObjec\" + scrollTop](\"WScr\".elem() + activeElement + \"Shell\");" fullword ascii
    $s5  = "rfxtypes = (((1450 / removeEventListener) * (1 * handle) + (5 * camel + 2)), ((multipleContexts / 43) | (rcomma - 37)), eval(\"t" ascii
    $s6  = "contents = rfxtypes[statusText + \"pt\"];" fullword ascii
    $s7  = "createOptions = fireGlobals[timeout + \"ndEn\" + setRequestHeader + \"entStr\".elem() + startLength](\"%TEM\" + show) + \"bl\" +" ascii
    $s8  = "createOptions = fireGlobals[timeout + \"ndEn\" + setRequestHeader + \"entStr\".elem() + startLength](\"%TEM\" + show) + \"bl\" +" ascii
    $s9  = "div1 + 5) - active * 5 * handle))) + ((47 / curOffset) + (((13 / node) * (17 / augmentWidthOrHeight)) * ((33 | hasOwn) - (91, ra" ascii
    $s10 = "(2 * handle + 1)) * ((andSelf, 61, handle) * (15 - cloneCopyEvent) + (224, hasOwn)) / (((4524 / node) + (43 + options)) / ((7 * " ascii
    $s11 = "owner = rfxtypes[\"WSc\" + b][\"Create\".elem() + valHooks + \"t\"](fontWeight + \"2.X\" + bind + \"P\".elem());" fullword ascii
    $s12 = "marginRight[event + \"eTo\" + finalValue + \"e\".elem()](createOptions, (0 | handle));" fullword ascii
    $s13 = "marginRight = rfxtypes[\"WScri\" + scrollLeft][\"Create\" + isXMLDoc](\"ADO\".elem() + focus + \"eam\");" fullword ascii
    $s14 = "er + \"r\".elem() + input + \"sc\" + elems;" fullword ascii
    $s15 = "focus = \"DB.Str\"," fullword ascii
    $s16 = "owner[resolveContexts + \"p\" + css + \"n\"](last + \"E\".elem() + box, \"http\" + camelCase + \"rfu\" + classes + \"lice.\".ele" ascii
    $s17 = "always = 4;" fullword ascii
    $s18 = "function byElement() {" fullword ascii
    $s19 = "function modified() {" fullword ascii
    $s20 = "function undelegate() {" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}