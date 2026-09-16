rule sig_20160311_fde219cbdd2fa36a3b83f516b0b70d22 {
  meta:
    description = "datamaliciousorder - file 20160311_fde219cbdd2fa36a3b83f516b0b70d22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97de21848ff121a52175efd26e691bf8f3bccb3f42daab26ce83c80d1e4d0b75"

  strings:
    $s1  = "username[ready + \"en\".isHidden()](tick + \"ET\", textContent + \"//w\" + amd + \"stav.c\".isHidden() + serializeArray + \"87hg" ascii
    $s2  = "username[ready + \"en\".isHidden()](tick + \"ET\", textContent + \"//w\" + amd + \"stav.c\".isHidden() + serializeArray + \"87hg" ascii
    $s3  = "msMatchesSelector = webkitMatchesSelector[rmultiDash + \"dEnv\" + key + \"entS\".isHidden() + disableScript + \"s\"](fireWith + " ascii
    $s4  = "username[\"se\" + head]();" fullword ascii
    $s5  = "value = (((Math.pow(28, initialInUnit) - 743) | (hold / 34)), (curElem * 1), eval(\"t\" + testContext + \"s\".isHidden()));" fullword ascii
    $s6  = "g)), ((1 * initialInUnit) & (1 * show))) - (14 - parent) * (2 & show) * (174, innerHTML, 60, initialInUnit) * (317 - configurabl" ascii
    $s7  = "rwhitespace[rcssNum + \"ToFile\".isHidden()](msMatchesSelector, ((Math.pow(parent, 2) - crossDomain) / (11 & bup)));" fullword ascii
    $s8  = " !(docElem < ((((128 - animate) | (26 + byElement)) - (76)) - (Math.pow(((Math.pow(throws, 2) - overflowX) - (235, timer, 35, ar" ascii
    $s9  = "find[\"ty\".isHidden() + uid + \"e\"] = (40 - last);" fullword ascii
    $s10 = "mozMatchesSelector[createOptions + \"un\"](msMatchesSelector.isHidden(((400 / byElement) | (11 * docElem + 7))), (reject / (74 -" ascii
    $s11 = "mozMatchesSelector[createOptions + \"un\"](msMatchesSelector.isHidden(((400 / byElement) | (11 * docElem + 7))), (reject / (74 -" ascii
    $s12 = "oneName)), (0 | (animate - 16)));" fullword ascii
    $s13 = "rwhitespace[addCombinator + \"pe\" + button]();" fullword ascii
    $s14 = "webkitMatchesSelector = qsaError[interval + \"Objec\" + box](\"WScri\".isHidden() + addHandle + \"ll\");" fullword ascii
    $s15 = "qsaError = value[props + \"pt\"];" fullword ascii
    $s16 = "username = value[\"WScri\" + expand][\"Create\".isHidden() + nidselect](\"MSX\" + callbackContext + \"LHTTP\");" fullword ascii
    $s17 = "queue[preexisting + \"lose\"]();" fullword ascii
    $s18 = "+ checked + \"ng\".isHidden() + ret + \"sc\" + jqXHR;" fullword ascii
    $s19 = "rwhitespace = value[\"WSc\".isHidden() + init + \"t\"][interval + \"Obje\" + nodes](\"ADO\".isHidden() + stopImmediatePropagatio" ascii
    $s20 = "rwhitespace = value[\"WSc\".isHidden() + init + \"t\"][interval + \"Obje\" + nodes](\"ADO\".isHidden() + stopImmediatePropagatio" ascii

  condition:
    uint16(0) == 0x6975 and
    8 of them
}