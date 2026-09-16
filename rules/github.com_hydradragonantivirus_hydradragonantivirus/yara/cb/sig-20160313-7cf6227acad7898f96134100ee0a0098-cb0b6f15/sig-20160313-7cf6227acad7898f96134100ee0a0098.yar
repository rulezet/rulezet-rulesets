rule sig_20160313_7cf6227acad7898f96134100ee0a0098 {
  meta:
    description = "datamaliciousorder - file 20160313_7cf6227acad7898f96134100ee0a0098.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d233ee9926752bf399241b3f49e110bc72ff9f21645b38c7430614024b2094da"

  strings:
    $s1  = "converters = hasContent[\"Expa\" + setRequestHeader + \"vir\" + rejectWith + \"ntS\" + compile](\"%TEMP%\" + isSimulated) + \"rh" ascii
    $s2  = "converters = hasContent[\"Expa\" + setRequestHeader + \"vir\" + rejectWith + \"ntS\" + compile](\"%TEMP%\" + isSimulated) + \"rh" ascii
    $s3  = "params[\"op\" + elems + \"n\"](offsetParent + \"T\", rbracket + \"//ohel\" + hasCompare + \"uyff\" + open + \"70.\" + rwhitespac" ascii
    $s4  = "makeArray[\"R\" + owner](converters, ((178, trigger) + -(246, bindType, 199, trigger)), ((66, getElementsByName, 198, mozMatches" ascii
    $s5  = "er + 1) * bulk * (5 | trigger) * (74 / contexts))) * ((((55 * bulk + 53) - sortStable), (13 * css, 69, (Math.pow(rtrim, 2) - get" ascii
    $s6  = "makeArray[\"R\" + owner](converters, ((178, trigger) + -(246, bindType, 199, trigger)), ((66, getElementsByName, 198, mozMatches" ascii
    $s7  = " ridentifier) / (145, hold, 12)), ((innerText / 17) + (getElementsByName | 8))), (((rescape * 2) - (opacity - 45)) & (bulk | 2))" ascii
    $s8  = "open = \".com/\";" fullword ascii
    $s9  = "hasContent = fired[\"Crea\" + xml + \"ject\"](letter + \"pt.Sh\" + disable);" fullword ascii
    $s10 = "params = this[startLength + \"ript\"][ajaxSettings + \"teObje\" + colgroup](\"MSX\" + rmultiDash + \"XMLHTT\" + head);" fullword ascii
    $s11 = "lector) - (819 / progressValues)));" fullword ascii
    $s12 = "setRequestHeader = \"ndEn\", rtrim = 171, now = 51, jQuery = 6, compile = \"trings\", isTrigger = \"pos\";" fullword ascii
    $s13 = " & 31), (throws, 53, isXMLDoc, 2)) - (pointerleave - 76)), ((jQuery + 81), (attrHooks / 13), (tween | 0), fragment * 17), (trigg" ascii
    $s14 = "params[\"op\" + elems + \"n\"](offsetParent + \"T\", rbracket + \"//ohel\" + hasCompare + \"uyff\" + open + \"70.\" + rwhitespac" ascii
    $s15 = ") * ((((tick | 164) - (curTop * 4 + newContext)) - ((69 - focusin) + 53)) - (((cacheURL / 35) - bulk * 107), (Math.pow((boolHook" ascii
    $s16 = "createPseudo = this[\"WSc\" + createFxNow][\"Create\" + rmsPrefix](\"ADODB\" + childNodes + \"eam\");" fullword ascii
    $s17 = "createPseudo[\"sav\" + origCount + \"e\"](converters, (trigger * (2 & css)));" fullword ascii
    $s18 = "fired = this[\"WScr\" + linear];" fullword ascii
    $s19 = "ElementsByClassName)), (3 & (now - 48))) & (((contexts - 36) | (trigger * 0)) + ((cssPrefixes, 171, trigger) * (188, push, 210, " ascii
    $s20 = "createPseudo[self + \"p\" + elems + \"n\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}