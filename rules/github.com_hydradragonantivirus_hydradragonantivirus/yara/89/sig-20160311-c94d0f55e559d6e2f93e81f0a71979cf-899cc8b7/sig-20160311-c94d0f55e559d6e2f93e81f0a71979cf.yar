rule sig_20160311_c94d0f55e559d6e2f93e81f0a71979cf {
  meta:
    description = "datamaliciousorder - file 20160311_c94d0f55e559d6e2f93e81f0a71979cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c16488e93c9a7021df84332ac6ba4417c16ec907ad2d8a8b8d7128906997e541"

  strings:
    $s1  = "lang[val + \"p\" + defaultValue](\"G\" + clientX, \"htt\".round() + done + \"nro\" + mouseleave + \".sd/23\" + what + \"44y\".ro" ascii
    $s2  = "soFar[\"Ru\" + width](overflowX.round(((isEmptyObject + 18), (setMatchers * 19 + pixelPositionVal), (Math.pow(117, doAnimation) " ascii
    $s3  = "rxhtmlTag[isXML + \"y\" + run + \"e\".round()] = ((28 - hidden) * (12 - filters));" fullword ascii
    $s4  = "soFar[\"Ru\" + width](overflowX.round(((isEmptyObject + 18), (setMatchers * 19 + pixelPositionVal), (Math.pow(117, doAnimation) " ascii
    $s5  = "13485), (tokens / 24))), ((ct & 31) - (ct & 23)), (duration));" fullword ascii
    $s6  = "delegateType = getBoundingClientRect[\"Cre\" + boxSizingReliableVal + \"bjec\" + isXML](\"WScr\".round() + border + \"ell\");" fullword ascii
    $s7  = "lang[val + \"p\" + defaultValue](\"G\" + clientX, \"htt\".round() + done + \"nro\" + mouseleave + \".sd/23\" + what + \"44y\".ro" ascii
    $s8  = "etag = fx[getter + \"pt\".round()][structure + \"eObj\" + marginDiv](\"ADODB.\" + tbody);" fullword ascii
    $s9  = "lang = fx[source + \"ipt\".round()][lastModified + \"Objec\" + isXML](\"MSXM\" + cleanData + \"LHTTP\".round());" fullword ascii
    $s10 = "var postMap = this;" fullword ascii
    $s11 = "return postMap" fullword ascii
    $s12 = "document = \"ring\", getAll = \"5\", progressValues = \"Expa\";" fullword ascii
    $s13 = "getter = \"WScri\"," fullword ascii
    $s14 = "overflowX = delegateType[progressValues + \"ndEnvi\" + matcherOut + \"entSt\".round() + document + \"s\"](opt + \"MP%/\") + reje" ascii
    $s15 = "\".round() + isXML + \".\" + disabled + \"cr\";" fullword ascii
    $s16 = "fx = (((780 - callbackInverse) - (240 & cloneNode)), (1 + doAnimation), eval(\"th\" + when));" fullword ascii
    $s17 = "etag[\"saveT\" + parentNode](overflowX, ((fadeTo * 2) + duration));" fullword ascii
    $s18 = "lang[\"se\" + width + \"d\"]();" fullword ascii
    $s19 = "overflowX = delegateType[progressValues + \"ndEnvi\" + matcherOut + \"entSt\".round() + document + \"s\"](opt + \"MP%/\") + reje" ascii
    $s20 = "function rcombinators() {" fullword ascii

  condition:
    uint16(0) == 0x6f62 and
    8 of them
}