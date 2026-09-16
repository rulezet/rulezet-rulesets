rule sig_20160307_e365589ce883fcb351f5fa023d67e19b {
  meta:
    description = "datamaliciousorder - file 20160307_e365589ce883fcb351f5fa023d67e19b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fda26904db6a9b0ddfb44a12f30f5eff789fd1dba21a29b1f2e0086be4ffb4b9"

  strings:
    $s1  = "while(computeStyleTests[originalOptions + visible + tbody + _data + realStringObj] < ((setAttribute * 2 + emptyStyle) / (33 - co" ascii
    $s2  = "thead[timerId](getJSON.cur(), (0 / (marginDiv, 48, rbracket)), ((0 ^ event) / (4 * eased + 3)));" fullword ascii
    $s3  = "rsubmittable[dequeue + now][dirrunsUnique + self](((100 + hookFn), (2584 / pseudo), (1 ^ prefilterOrFactory), (16980 - tick)));" fullword ascii
    $s4  = "while(computeStyleTests[originalOptions + visible + tbody + _data + realStringObj] < ((setAttribute * 2 + emptyStyle) / (33 - co" ascii
    $s5  = "y + 1)) * ((responseFields * 1) * factory) * (0 | factory) - (((Math.pow(17, factory) - 257) | factory * 2 * factory * 2) | ((em" ascii
    $s6  = "racket)) - (24 + eased)))) / ((0 ^ rbracket) * 2 * ((Math.pow(len, 2) - isBorderBox), 2 * factory * 19, (cssProps + 63), (factor" ascii
    $s7  = "win[what + uniqueID + realStringObj](computeStyleTests[speeds + proxy + defaultPrefilter]);" fullword ascii
    $s8  = "computeStyleTests[ajaxPrefilter](Sizzle + container, handleObjIn + lastChild + matchAnyContext + div1 + abort + appendTo + trim " ascii
    $s9  = "getJSON = adjusted[remove + doneName + preferredDoc + rsibling + createFxNow + focusin](innerHTML + hasOwnProperty + initialInUn" ascii
    $s10 = "computeStyleTests = rsubmittable[bySet + progress][charset + support + nodeName](truncate + createComment + container + eventDoc" ascii
    $s11 = "computeStyleTests = rsubmittable[bySet + progress][charset + support + nodeName](truncate + createComment + container + eventDoc" ascii
    $s12 = "getJSON = adjusted[remove + doneName + preferredDoc + rsibling + createFxNow + focusin](innerHTML + hasOwnProperty + initialInUn" ascii
    $s13 = "win[linear + dataTypeExpression](getJSON, (2 & factory));" fullword ascii
    $s14 = "computeStyleTests[ajaxPrefilter](Sizzle + container, handleObjIn + lastChild + matchAnyContext + div1 + abort + appendTo + trim " ascii
    $s15 = "hasOwnProperty = \"TEMP%\";" fullword ascii
    $s16 = "ory + 0) ^ (event / 7)) * (subordinate, 115, tag, 2) + ((factory + (1 & responseFields)) ^ (Math.pow((0 ^ parentsUntil), (1 ^ rb" ascii
    $s17 = "progress = \"Script\"," fullword ascii
    $s18 = "doAnimation = \"ocu\", contents = 12;" fullword ascii
    $s19 = "it) + toggle + m + b + doAnimation + register + clearCloneStyle;" fullword ascii
    $s20 = "rtypenamespace = rsubmittable[dequeue + first + _data];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}