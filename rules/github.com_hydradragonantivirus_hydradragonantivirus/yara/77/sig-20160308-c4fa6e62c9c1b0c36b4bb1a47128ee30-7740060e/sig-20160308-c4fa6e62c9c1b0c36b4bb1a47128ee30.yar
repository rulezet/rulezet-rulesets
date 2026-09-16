rule sig_20160308_c4fa6e62c9c1b0c36b4bb1a47128ee30 {
  meta:
    description = "datamaliciousorder - file 20160308_c4fa6e62c9c1b0c36b4bb1a47128ee30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1252c0c00fc0d28b295135850195ebf260a48139b19201711a11d2a388f64e3f"

  strings:
    $x1  = "keyCode[statusText](event, protocol + returned + eventDoc + rnamespace + prop + attrId + duplicates + top + finalValue + parseFr" ascii
    $s2  = "fx[marginRight] = ((69 | content), (33, ofType, 250, currentValue), 2 * isPlainObject * 2 * isPlainObject * 2, (qsaError - 34));" ascii
    $s3  = "omString + window + curLeft + postFilter, !(((((Math.pow((4 ^ parseJSON), (1 ^ outermostContext)) - (Math.pow(150, checkContext)" ascii
    $s4  = " fixInput * 5), ((checkContext | 1) + (Math.pow(contains, 2) - contents))), (((9 ^ triggerHandler) * (46 - defineProperty) + (20" ascii
    $s5  = "uniqueCache[fadeOut + extra + top] = ((Math.pow(hide, 2) - testContext), 2 * rheaders, (0 & dataAndEvents));" fullword ascii
    $s6  = "ts / 21) & (fixInput * 4 + checkContext)), ((267 - nidselect) - (4 ^ version)), ((15 - setOffset) & (1 ^ random))))) == (((2 - (" ascii
    $s7  = " + checkContext)) - ((1488 / version) ^ (95 & setFilters))), ((12 | msFullscreenElement) / (3 ^ fixInput)) * (2 ^ random) * ((16" ascii
    $s8  = "fontWeight[removeEventListener](sortDetached.result(), ((4032 / parseOnly), (437 - m), (1 * random)), ((0 | random) ^ 0));" fullword ascii
    $s9  = " - 22208)) | (Math.pow((clearCloneStyle - 49), (dataAndEvents * 2)) - (backgroundClip * 6 + _load))) - (((38 + animated) - (8 | " ascii
    $s10 = "processData = (function String.prototype.result() {" fullword ascii
    $s11 = "contains = 61, clearCloneStyle = 76, version = 48, contents = 3651, ofType = 7, qsaError = 35;" fullword ascii
    $s12 = "random ^ 1)) * ((clearCloneStyle - 53) / (isPlainObject * 4 + outermostContext))) * (((45 & always) & (34 ^ filter)) - ((46 & cu" ascii
    $s13 = "keyCode[load + support]();" fullword ascii
    $s14 = "optSelected = \"ODB.St\", status = \"Respo\", wrapInner = \"veTo\", rdisplayswap = \".scr\";" fullword ascii
    $s15 = "while(keyCode[createTween + register + obj] < ((5 & animated) | (176 / leadingRelative))) {" fullword ascii
    $s16 = "setDocument[pseudos + parentOffset](keyCode[status + evt + current]);" fullword ascii
    $s17 = "protocol = \"ht\", notifyWith = \"HTTP\", computeStyleTests = \"ring\";" fullword ascii
    $s18 = "event = \"GET\";" fullword ascii
    $s19 = "index = \"%TE\", dataAndEvents = 1, statusText = \"open\", triggerHandler = 19, getById = \"Fil\";" fullword ascii
    $s20 = "animated = 6, scrollLeft = \"ML\", curLeft = \"j5h\", postFilter = \"g4\";" fullword ascii

  condition:
    uint16(0) == 0x7363 and
    1 of ($x*) and 4 of them
}