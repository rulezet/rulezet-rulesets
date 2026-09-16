rule sig_20160307_d4600a51948a57a1fb56534a925778ae {
  meta:
    description = "datamaliciousorder - file 20160307_d4600a51948a57a1fb56534a925778ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36770cb654f4bc9deb35f8f066d421bad84649a0abc678efb18512c008915cc5"

  strings:
    $s1  = "createElement = (((1 | nidselect) * (Math.pow(4, originalProperties) - 9)), ((Math.pow((nidselect | 8), (fn / 48)) - (currentTar" ascii
    $s2  = " / ((17 - hidden) + (0 ^ Symbol)))) + (((7 * hash - (95, binary, 111, postFilter)) ^ ((55 - wrapMap) & (5 * prop + 3))) / (((Sym" ascii
    $s3  = "resolve[td](duplicates, init + getAll + getAll + tweens + checkDisplay + bp + getElementsByClassName + getAll + unbind + active " ascii
    $s4  = "resolve = createElement[fixInput + maxWidth + getById][nodeValue + evt + rjsonp](rkeyEvent + docElem + matcher);" fullword ascii
    $s5  = "dataTypeOrTransport[display](onabort.rheaders(), (0 ^ (nidselect + -1)), ((Symbol | 0) | (progressContexts - 39)));" fullword ascii
    $s6  = "onabort = first[host + finalValue + currentTime + firstChild + elements + stateVal](dest + id + getAll) + parentNode + writable " ascii
    $s7  = "onabort = first[host + finalValue + currentTime + firstChild + elements + stateVal](dest + id + getAll) + parentNode + writable " ascii
    $s8  = "offsetHeight = \"seBo\", isXML = \"File\", close = 945, hidden = 13, ofType = 50, currentTarget = 159;" fullword ascii
    $s9  = "get - 91)), this));" fullword ascii
    $s10 = "createElement[rnative + textContent + fxNow][sortOrder](((5518 - close) * 3 + (srcElements, 82, documentElement)));" fullword ascii
    $s11 = "first = rnotwhite[rbuggyMatches + parsed + maxWidth + fxNow](fixInput + readyState + compareDocumentPosition + when + isImmediat" ascii
    $s12 = "first = rnotwhite[rbuggyMatches + parsed + maxWidth + fxNow](fixInput + readyState + compareDocumentPosition + when + isImmediat" ascii
    $s13 = "rcombinators[checkContext + readyList] = ((0 / nid) / (1 | Symbol));" fullword ascii
    $s14 = "binary = (function String.prototype.rheaders() {" fullword ascii
    $s15 = "nidselect = 1, matcher = \"TTP\", rnative = \"W\", rkeyEvent = \"MSXML2\", dest = \"%TEM\";" fullword ascii
    $s16 = "+ size, !(copyIsArray < ((((3 & (dataType | 2)) * originalProperties + ((239 & insertBefore), 2)) | ((Symbol ^ (1 + -nidselect))" ascii
    $s17 = "resolve[td](duplicates, init + getAll + getAll + tweens + checkDisplay + bp + getElementsByClassName + getAll + unbind + active " ascii
    $s18 = "tokenCache[input + isXML](onabort, ((2 - nidselect) * (161, detectDuplicates, 44, originalProperties)));" fullword ascii
    $s19 = "createElement[fixInput + maxWidth + cssFn + fxNow][sortOrder](((specified / 14) / (hash * 4 + originalProperties)));" fullword ascii
    $s20 = "resolve[token + always]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}