rule sig_20160311_c800b5fe14a9309981236f200ead5218 {
  meta:
    description = "datamaliciousorder - file 20160311_c800b5fe14a9309981236f200ead5218.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d6154c39eb3f826f2152b3b8e07cd93d9bbc17bab08aa406d1411696c4f9d6a"

  strings:
    $s1  = "setMatcher = processData[src + \"dEnvir\" + map + \"Stri\".module() + tween](\"%TEMP\" + checkDisplay) + \"rscri\" + nodeName + " ascii
    $s2  = "setMatcher = processData[src + \"dEnvir\" + map + \"Stri\".module() + tween](\"%TEMP\" + checkDisplay) + \"rscri\" + nodeName + " ascii
    $s3  = "raw[\"op\" + delegate + \"n\".module()](clearCloneStyle + \"T\", second + \"p:/\" + attrHooks + \"omstav\".module() + each + \"0" ascii
    $s4  = ") / (Math.pow((13 + now) * ((21 + disable) - (10 | overrideMimeType)), (((1 + now) * (53 - add)) | (0 / tweener))) - (((346 - rh" ascii
    $s5  = "reject[eventDoc + \"yp\" + delegate] = ((overrideMimeType & 31) - (overflowY & 29));" fullword ascii
    $s6  = "original[\"Ru\" + optSelected](setMatcher.module(((1901 + rxhtmlTag) / (57 - reset))), ((42 & add) - (32 | setMatched)), (2 * rr" ascii
    $s7  = "original = processData;" fullword ascii
    $s8  = "ate, !((((((owner / 43) | rreturn * 2 * rreturn * 2) | (Math.pow((vendorPropName / 27), (name / 20)) - (offsetHeight / 13))) - (" ascii
    $s9  = "each = \".com/\";" fullword ascii
    $s10 = "((removeProp - 10) * (escapedWhitespace, 2) + implicitRelative * 2) | ((compile, 64) | (Math.pow(namespace, 2) - hasDuplicate)))" ascii
    $s11 = "raw = doneName[getAll + \"pt\"][defineProperty + \"ateO\" + status + \"t\".module()](MAX_NEGATIVE + \".XMLHT\" + collection);" fullword ascii
    $s12 = "tml) - (110 & width)) * (10 - (flatOptions & 7)) + rreturn * 2 * (now | 2) * rreturn))) > 2));" fullword ascii
    $s13 = "original[\"Ru\" + optSelected](setMatcher.module(((1901 + rxhtmlTag) / (57 - reset))), ((42 & add) - (32 | setMatched)), (2 * rr" ascii
    $s14 = "timer[\"saveT\" + curLeft](setMatcher, ((16 - eased) | (44 / size)));" fullword ascii
    $s15 = "raw[\"op\" + delegate + \"n\".module()](clearCloneStyle + \"T\", second + \"p:/\" + attrHooks + \"omstav\".module() + each + \"0" ascii
    $s16 = "raw[\"s\" + delegate + \"n\".module() + tuple]();" fullword ascii
    $s17 = "dule() + active + \"ed\" + document + \"s\" + t + \"r\".module();" fullword ascii
    $s18 = "timer[guid + \"p\".module() + delegate + \"n\"]();" fullword ascii
    $s19 = "timer = doneName[\"WScrip\" + eventDoc][\"Cre\" + rfxtypes + \"bjec\".module() + eventDoc](\"ADODB.\" + view + \"eam\");" fullword ascii
    $s20 = "unbind();" fullword ascii

  condition:
    uint16(0) == 0x7774 and
    8 of them
}