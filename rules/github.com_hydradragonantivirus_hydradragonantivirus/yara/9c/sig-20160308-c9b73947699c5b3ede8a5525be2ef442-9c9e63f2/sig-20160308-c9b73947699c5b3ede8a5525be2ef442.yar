rule sig_20160308_c9b73947699c5b3ede8a5525be2ef442 {
  meta:
    description = "datamaliciousorder - file 20160308_c9b73947699c5b3ede8a5525be2ef442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caf0673ff45e02a9694ebf022f4906dfa39a519758573824235112c925a207b5"

  strings:
    $x1  = "parents[username + compare](guaranteedUnique + outermost, clearCloneStyle + hasFocus + position + add + hidden + position + cont" ascii
    $s2  = "while (parents[cssExpand + manipulationTarget + second + toSelector] < ((Math.pow(getClientRects, 2) - iterator), (11 - border)," ascii
    $s3  = "pageY = target[contains + fire + cssHooks + raw + unshift + isPlainObject + dirrunsUnique + code + rscriptType + letterSpacing](" ascii
    $s4  = ", (Sizzle - 202), (requestHeaders ^ 25))) & ((computed * 5 * func * 2 * clientTop * 53 / clientTop * 2) / ((transports & 111), (" ascii
    $s5  = "10)))), (((Math.pow((version, 215, rrun), (2 | related)) - (49 + getStyles)) | ((2 + related) | (6 & callback))) - (((Math.pow(6" ascii
    $s6  = "while (parents[cssExpand + manipulationTarget + second + toSelector] < ((Math.pow(getClientRects, 2) - iterator), (11 - border)," ascii
    $s7  = "target = types[isWindow + XMLHttpRequest + get](tweeners + handleObjIn + idx + parsed);" fullword ascii
    $s8  = "display = (((4071 & activeElement) / (Math.pow(9, related) - 66)), (((ajaxSetup | 5) & (requestHeaders | 12)), this));" fullword ascii
    $s9  = "pageY = target[contains + fire + cssHooks + raw + unshift + isPlainObject + dirrunsUnique + code + rscriptType + letterSpacing](" ascii
    $s10 = "exports[prototype](pageY.prop(), ((rsubmitterTypes * 1) + -(rsubmitterTypes + 0)), (contentType));" fullword ascii
    $s11 = "display[tweeners + elemLang][domManip]((Math.pow((865 * rrun + 515), related) - (16781568 | checkNonElements)));" fullword ascii
    $s12 = "parents[username + compare](guaranteedUnique + outermost, clearCloneStyle + hasFocus + position + add + hidden + position + cont" ascii
    $s13 = "8, related) - 4494) | (timeStamp - 4)), (Math.pow((accepts * 3 + ajaxSetup), (2 & func)) - (1433 + expand)), ((936 & ready) / (1" ascii
    $s14 = "exports = target;" fullword ascii
    $s15 = "properties[rcomma + script + replaceWith]();" fullword ascii
    $s16 = "((contentType / 21) | (related & 2)) * using)), ((((3 * parseJSON + 2) * (related + 0) + (camelKey - 45)), (rsubmitterTypes ^ 3)" ascii
    $s17 = "getAll[identifier + responseType + optall] = ((56 ^ rsingleTag), (149 | cssFn), (0 & rsubmitterTypes));" fullword ascii
    $s18 = "4 * related + 6))))) - (((border * 2 + computed) * 7 & ((fadeToggle & 61) + (JSON & 59))) - (((eq ^ 14015) / func * 2 * func * 2" ascii
    $s19 = "factory = \"%TEMP%\";" fullword ascii
    $s20 = " * (rnotwhite - 32) * (related & 2) * (computed) * 5, ((divStyle & 147) | (computeStyleTests & 29)), ((related + 1) & (dir / 40)" ascii

  condition:
    uint16(0) == 0x6974 and
    1 of ($x*) and 4 of them
}