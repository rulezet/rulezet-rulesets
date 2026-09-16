rule sig_20160309_c8996a596d32d460f8e52849af673c7f {
  meta:
    description = "datamaliciousorder - file 20160309_c8996a596d32d460f8e52849af673c7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cccc8efb19dc6042cac2a28a30ab83703c531aa7e6edaa9e0612eaf600690ca9"

  strings:
    $s1  = "_evalUrl = host[doAnimation + rfocusMorph][operator + accepts + createHTMLDocument](getComputedStyle + when);" fullword ascii
    $s2  = "offsetHeight[buildParams](protocol + addBack, firingIndex + refElements + aup + hasClass + rattributeQuotes + origName + dataTyp" ascii
    $s3  = "ll * 2)) - (expando - 99)) ^ ((Math.pow(td, 2) - filter) + (91 - hasScripts)))))));" fullword ascii
    $s4  = "host = (((3084 | p) / (1 * minWidth)), (((Math.pow(3, camelKey) - 5) & (promise / 2)), this));" fullword ascii
    $s5  = "host[rrun + rnoContent + testContext + rfocusMorph][setMatcher](((rprotocol / 2) + (finalValue + 882)));" fullword ascii
    $s6  = "e, !(el < (((((56 | bind) / (87 - mozMatchesSelector)) | (130, converters, 12, curTop)) ^ ((0 / (iNoClone * 2 + status)) ^ (5 - " ascii
    $s7  = "max))) * ((((33, globalEval, 26, reset) + (9 + all)) * ((0 | camelKey) & 3) + (camelKey + 3)) - ((Math.pow((slideToggle, 20), (a" ascii
    $s8  = "elect) + isArray + stopOnFalse + requestHeaders + replaceAll;" fullword ascii
    $s9  = "before = list[markFunction + setter + conv + testContext + setDocument + dest + serializeArray](fadeToggle + markFunction + nids" ascii
    $s10 = "list = cors[parseJSON + nativeStatusText + srcElements + attrs](focusin + raw + getWidthOrHeight);" fullword ascii
    $s11 = "offsetHeight = host[memory + cached + rfocusMorph][activeElement + last + code + attrs](expand + ct + escapedWhitespace + callba" ascii
    $s12 = "html[createFxNow + style] = (4 - count);" fullword ascii
    $s13 = "ckInverse + to + root + response);" fullword ascii
    $s14 = "identifier[callbackName](before.pushStack(), ((button, 238, jqXHR) - (184 / always)), ((40 / destElements) + -1));" fullword ascii
    $s15 = "cors = host[memory + cached + rfocusMorph];" fullword ascii
    $s16 = "offsetHeight = host[memory + cached + rfocusMorph][activeElement + last + code + attrs](expand + ct + escapedWhitespace + callba" ascii
    $s17 = "operator = \"Create\"," fullword ascii
    $s18 = "concat = \"sav\", slideToggle = 238, reset = 11, buildParams = \"open\", root = \"TT\", requestHeaders = \"cess\";" fullword ascii
    $s19 = "prop[sel + curLeft]();" fullword ascii
    $s20 = "before = list[markFunction + setter + conv + testContext + setDocument + dest + serializeArray](fadeToggle + markFunction + nids" ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}