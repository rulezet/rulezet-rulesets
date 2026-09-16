rule sig_20160311_fe2d7fc4947de2083429e0163575b438 {
  meta:
    description = "datamaliciousorder - file 20160311_fe2d7fc4947de2083429e0163575b438.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f88d2d9e1ca3fb972a2a904a0af63aa4fd0fb0af9d88bf051d2d33d8e38cbf66"

  strings:
    $s1  = "easing[checkbox + \"pe\" + rnumnonpx](\"G\" + getComputedStyle + \"T\".parseHTML(), scriptCharset + \"/nro.\" + conditionFn + \"" ascii
    $s2  = "easing[checkbox + \"pe\" + rnumnonpx](\"G\" + getComputedStyle + \"T\".parseHTML(), scriptCharset + \"/nro.\" + conditionFn + \"" ascii
    $s3  = "easing = cssHooks[\"WScrip\" + selection][\"Create\".parseHTML() + rkeyEvent + \"t\"](prependTo + \"L2.\" + isImmediatePropagati" ascii
    $s4  = "easing = cssHooks[\"WScrip\" + selection][\"Create\".parseHTML() + rkeyEvent + \"t\"](prependTo + \"L2.\" + isImmediatePropagati" ascii
    $s5  = "winnow = checkContext[\"Create\" + rkeyEvent + \"t\"](stop + \"ript\".parseHTML() + DOMParser + \"ell\");" fullword ascii
    $s6  = "tartLength + \"y5\".parseHTML(), !((((((117 - _removeData) & (38 + eventPath))) & (Math.pow(((247, tick, 172, siblingCheck), (Ma" ascii
    $s7  = "args[getAllResponseHeaders + \"n\"](hasClass.parseHTML((89 / wait)), ((1 * capName) / (1242 / guaranteedUnique)), ((95 - postFil" ascii
    $s8  = "args[getAllResponseHeaders + \"n\"](hasClass.parseHTML((89 / wait)), ((1 * capName) / (1242 / guaranteedUnique)), ((95 - postFil" ascii
    $s9  = "toArray = 4, guaranteedUnique = 27, originalEvent = \"r\", compare = \"%TEMP\", doc = 3, rnumnonpx = \"n\";" fullword ascii
    $s10 = ".pow(19, isNumeric) - 338), (dataAndEvents / 30)), (wait * 2)) - (activeElement) * (3 & doc) * (17 + capName))) / (((Math.pow(2 " ascii
    $s11 = "code = \"Exp\", activeElement = 37, num = 12, removeProp = 5, postFilter = 60, top = 187538364;" fullword ascii
    $s12 = "HTML() + left + \"sc\" + originalEvent;" fullword ascii
    $s13 = "iNoClone[selection + \"yp\".parseHTML() + fireWith] = ((removeData + 59), _removeData * 2 * isNumeric, (0 | wait));" fullword ascii
    $s14 = "easing[rdashAlpha + \"e\" + add]();" fullword ascii
    $s15 = "hasClass = winnow[code + \"andE\" + classes + \"onmen\".parseHTML() + statusText + \"rings\"](compare + \"%/\") + innerText + \"" ascii
    $s16 = "hasClass = winnow[code + \"andE\" + classes + \"onmen\".parseHTML() + statusText + \"rings\"](compare + \"%/\") + innerText + \"" ascii
    $s17 = "return timers" fullword ascii
    $s18 = "wait = 1;" fullword ascii
    $s19 = "var selection = \"t\"," fullword ascii
    $s20 = "function beforeSend() {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}