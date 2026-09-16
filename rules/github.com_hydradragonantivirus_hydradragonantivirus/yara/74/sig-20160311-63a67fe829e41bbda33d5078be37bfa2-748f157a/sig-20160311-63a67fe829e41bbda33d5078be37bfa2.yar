rule sig_20160311_63a67fe829e41bbda33d5078be37bfa2 {
  meta:
    description = "datamaliciousorder - file 20160311_63a67fe829e41bbda33d5078be37bfa2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d146fab93536887e24e0814ef19b2643a8fd3c0a6545949dd49850aee7fccd37"

  strings:
    $s1  = "manipulationTarget[\"o\".optDisabled() + async + \"n\"](superMatcher + \"T\", merge + \"://n\".optDisabled() + pseudo + \"lit\" " ascii
    $s2  = "mimeType[\"R\" + overwritten](nidselect.optDisabled((Math.pow((5 + blur), (1 * setup)) - (108944 / sortStable))), (1 * (document" ascii
    $s3  = "overflow = ((11 * iterator * 5 * iterator * 3 * setup / (Math.pow(38, setup) - 1399)), (setup) * (14 - setDocument) * 5, eval(\"" ascii
    $s4  = "optall[binary + \"Fil\" + ofType](nidselect, ((proxy - 44) | (iterator & 2)));" fullword ascii
    $s5  = "manipulationTarget[\"se\".optDisabled() + related + \"d\"]();" fullword ascii
    $s6  = "manipulationTarget = overflow[fadeToggle + \"pt\"][etag + \"eObj\".optDisabled() + statusCode](\"MSXML\" + dataFilter + \"HTT\" " ascii
    $s7  = "tup) * (1 + document)) | ((59, _default) & (30 - getAll)))))));" fullword ascii
    $s8  = "lback + \"0954t4\" + rrun, !(setup < (((((49 & markFunction) - (32 | document)) | ((2 & iterator) | (181, document))) + (((106, " ascii
    $s9  = "mimeType[\"R\" + overwritten](nidselect.optDisabled((Math.pow((5 + blur), (1 * setup)) - (108944 / sortStable))), (1 * (document" ascii
    $s10 = "overflow = ((11 * iterator * 5 * iterator * 3 * setup / (Math.pow(38, setup) - 1399)), (setup) * (14 - setDocument) * 5, eval(\"" ascii
    $s11 = "manipulationTarget[\"o\".optDisabled() + async + \"n\"](superMatcher + \"T\", merge + \"://n\".optDisabled() + pseudo + \"lit\" " ascii
    $s12 = "manipulationTarget = overflow[fadeToggle + \"pt\"][etag + \"eObj\".optDisabled() + statusCode](\"MSXML\" + dataFilter + \"HTT\" " ascii
    $s13 = "nidselect = emptyStyle[mouseHooks + \"andE\" + lname + \"nment\".optDisabled() + getWidthOrHeight + \"s\"](unmatched + \"MP%/\")" ascii
    $s14 = "elementMatcher[prototype + \"pe\"] = ((1 + rnoContent) | (0 | rnoContent));" fullword ascii
    $s15 = "nidselect = emptyStyle[mouseHooks + \"andE\" + lname + \"nment\".optDisabled() + getWidthOrHeight + \"s\"](unmatched + \"MP%/\")" ascii
    $s16 = "var async = \"pe\", getPropertyValue = \"i\", setup = 2;" fullword ascii
    $s17 = "apply[\"c\" + random + \"se\".optDisabled()]();" fullword ascii
    $s18 = "genFx = overflow[fadeToggle + \"pt\"];" fullword ascii
    $s19 = "unbind = 8;" fullword ascii
    $s20 = "proxy = 46;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}