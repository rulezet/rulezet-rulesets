rule sig_20160307_abb19046a0ac573543b9f1192338cd56 {
  meta:
    description = "datamaliciousorder - file 20160307_abb19046a0ac573543b9f1192338cd56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81b25b8410cd7bc5a5dd249074739dac135142eca4bd43f2d2464644bd7a193d"

  strings:
    $s1  = "thead[augmentWidthOrHeight + on] = ((boolHook / 38), (restoreScript ^ 1), (createDocumentFragment - 120), (speed, 141, getClass)" ascii
    $s2  = "docElem[getPropertyValue + disableScript](soFar[originalOptions + animation + init]);" fullword ascii
    $s3  = "soFar[apply](namespace + allTypes, udataCur + factory + addClass + parseJSON + serialize + test + originalSettings + offset + ca" ascii
    $s4  = "thead[augmentWidthOrHeight + on] = ((boolHook / 38), (restoreScript ^ 1), (createDocumentFragment - 120), (speed, 141, getClass)" ascii
    $s5  = "grep = ((Math.pow(7 * jqXHR * 5 * dir, 2) - (href, 123, compiled, 43866)), ((jqXHR + 0) * (marginDiv, 179, jqXHR) * (76 / stopIm" ascii
    $s6  = "pipe[filter] = ((unmatched - 33) | (createHTMLDocument * 1));" fullword ascii
    $s7  = "docElem[finalDataType + handlerQueue + forward](pointerleave, ((9 + transports) / (0 ^ rdisplayswap)));" fullword ascii
    $s8  = "scrollTop) & (13 & addEventListener)) ^ (4 | now))) + ((((4 & suffix) - (1 + getClass)) & ((1 + -createHTMLDocument) ^ (116, gua" ascii
    $s9  = "cheLength, !(((((Math.pow(3, (dir & 3)) - (Math.pow(suffix, 2) - scrollTop)) + ((191 & invert) / (21 & isBorderBox))) - (((236, " ascii
    $s10 = "thead = pipe;" fullword ascii
    $s11 = "self = \"WScrip\", originalSettings = \"bd.com\", pageY = \".sc\";" fullword ascii
    $s12 = "while (soFar[extra + fireWith + disableScript] < ((jqXHR & 2) ^ (replaceChild / 18))) {" fullword ascii
    $s13 = "pointerleave = responseType[originAnchor + step + prev + sibling + th + whitespace + mimeType + tweens](second + rheaders) + inn" ascii
    $s14 = "pointerleave = responseType[originAnchor + step + prev + sibling + th + whitespace + mimeType + tweens](second + rheaders) + inn" ascii
    $s15 = "grep[_jQuery + _data][rnotwhite + result](((sortDetached & 93) ^ (prototype - 0)));" fullword ascii
    $s16 = "curTop = grep[self + addToPrefiltersOrTransports];" fullword ascii
    $s17 = "docElem = grep[rreturn + marginLeft][shift + colgroup + doScroll + rnoInnerhtml + addToPrefiltersOrTransports](seed + len + hasO" ascii
    $s18 = "docElem = grep[rreturn + marginLeft][shift + colgroup + doScroll + rnoInnerhtml + addToPrefiltersOrTransports](seed + len + hasO" ascii
    $s19 = "pipe = docElem;" fullword ascii
    $s20 = "grep[_jQuery + _data][visible](((location + 114109) / (getClass | 22)));" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    8 of them
}