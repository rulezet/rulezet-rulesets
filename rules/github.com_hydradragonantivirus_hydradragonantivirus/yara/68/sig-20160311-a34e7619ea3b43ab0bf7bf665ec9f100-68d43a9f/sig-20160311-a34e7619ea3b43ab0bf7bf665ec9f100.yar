rule sig_20160311_a34e7619ea3b43ab0bf7bf665ec9f100 {
  meta:
    description = "datamaliciousorder - file 20160311_a34e7619ea3b43ab0bf7bf665ec9f100.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a94932b6250d0b6422685246679323cec8c9274b755dec421d65cd86c0ffa98"

  strings:
    $s1  = "guaranteedUnique[statusText + \"en\"](onabort + \"E\".globalEval() + simple, \"http:/\" + booleans + \"dicke\" + l + \"8774\".gl" ascii
    $s2  = "acket)) * ((8 + addClass) - (Math.pow(29, rparentsprev) - 794)))) * ((Math.pow(((wait - 1181) / (getComputedStyle * 2 + response" ascii
    $s3  = ", (Math.pow((parseFromString), (14 - bulk)) - (Math.pow(2981, rparentsprev) - 8882497)), ((speeds + 51) | (fail - 62)), (rparent" ascii
    $s4  = ")), (((20 - bulk) - (64 - Data)) | ((20 * nextUntil + 12) * (hash | 2))), (((createHTMLDocument) & (140 | newSelector)) - (2 * r" ascii
    $s5  = "pixelMarginRight = \"Object\", l = \"m.com/\", wait = 3656, replaceWith = 11, elementMatcher = \"WScri\";" fullword ascii
    $s6  = "Fields)), ((58 / cssFn))) - ((3079 + status) - (381 * hasCompare + 334))) / (((letterSpacing & 16029) / (sel, 79, useCache, 33))" ascii
    $s7  = "parentsprev * 2 * rparentsprev * 11 & (pseudos / 41))), ((hash | 2) + ((hash | 0) / (rbracket + 0)))) == ((((rbracket | (1 & rbr" ascii
    $s8  = "guaranteedUnique[statusText + \"en\"](onabort + \"E\".globalEval() + simple, \"http:/\" + booleans + \"dicke\" + l + \"8774\".gl" ascii
    $s9  = "visibility = matcherFromGroupMatchers[rmultiDash + \"ndEnv\" + isEmptyObject + \"nme\".globalEval() + firstDataType + \"ngs\"](s" ascii
    $s10 = " \"P%/\") + mouseleave + \"cess\".globalEval() + onreadystatechange + \"s\" + detectDuplicates + \"s\" + version;" fullword ascii
    $s11 = "visibility = matcherFromGroupMatchers[rmultiDash + \"ndEnv\" + isEmptyObject + \"nme\".globalEval() + firstDataType + \"ngs\"](s" ascii
    $s12 = "shift[\"ty\" + showHide + \"e\".globalEval()] = (rbracket * 1);" fullword ascii
    $s13 = "newContext[subordinate + \"File\"](visibility, (rparentsprev));" fullword ascii
    $s14 = "attrNames = 3370, version = \"cr\", curOffset = 43;" fullword ascii
    $s15 = "hash = 0," fullword ascii
    $s16 = "charCode = 60, fail = 79, markFunction = 35, removeEvent = \"hi\", subordinate = \"saveTo\";" fullword ascii
    $s17 = "return rjsonp" fullword ascii
    $s18 = "soFar = \"%TEM\";" fullword ascii
    $s19 = "function preventDefault() {" fullword ascii
    $s20 = "select();" fullword ascii

  condition:
    uint16(0) == 0x7375 and
    8 of them
}